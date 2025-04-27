import requests
import hashlib
import hmac
import datetime
import os
import io

# --- AWS Signature V4 Helper Functions (Simplified) ---
# (In a real application, use a dedicated library or implement these robustly)
def parse_aws_timestamp(aws_timestamp: str) -> datetime.datetime:
    """Convert AWS timestamp format to datetime object.
    
    Args:
        aws_timestamp: AWS timestamp in format 'YYYYMMDDTHHMMSSZ'
    
    Returns:
        datetime object
    """
    # Parse the timestamp string
    # Format: YYYYMMDDTHHMMSSZ
    year = int(aws_timestamp[0:4])
    month = int(aws_timestamp[4:6])
    day = int(aws_timestamp[6:8])
    hour = int(aws_timestamp[9:11])
    minute = int(aws_timestamp[11:13])
    second = int(aws_timestamp[13:15])
    
    # Create datetime object
    return datetime.datetime(
        year=year,
        month=month,
        day=day,
        hour=hour,
        minute=minute,
        second=second,
        tzinfo=datetime.timezone.utc
    )
        
def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def get_signature_key(key, date_stamp, region_name, service_name):
    k_date = sign(('AWS4' + key).encode('utf-8'), date_stamp)
    k_region = sign(k_date, region_name)
    k_service = sign(k_region, service_name)
    k_signing = sign(k_service, 'aws4_request')
    return k_signing

def hash_sha256(data):
    # If data is string, encode it first
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()

# --- Configuration ---
access_key = 'MAKI9JGZYIXE6ARQCKZ1'
secret_key = 'dYdcCs9y1CmKTcvwtZCWEERdK8i3S8hkGh83aYo7'
region = 'us-east-1'
service = 's3'
bucket_name = 'mybucket'
object_key = 'your-streaming-object.txt'
file_path = 'local_file_to_upload.txt' # The file you want to upload

host = f'172.20.123.123'
endpoint = f'http://{host}/{bucket_name}/{object_key}'
content_type = 'application/octet-stream' # Or appropriate type
chunk_size_bytes = 64 * 1024 # Example: 64KB chunks

# --- 1. Prepare Initial Request Details ---
t = datetime.datetime.utcnow()
#t = parse_aws_timestamp('20250427T043824Z')
amz_date = t.strftime('%Y%m%dT%H%M%SZ')
date_stamp = t.strftime('%Y%m%d')
credential_scope = f'{date_stamp}/{region}/{service}/aws4_request'
file_size = os.path.getsize(file_path)

# --- 2. Calculate Initial ("Seed") Signature ---
signing_key = get_signature_key(secret_key, date_stamp, region, service)

# Canonical Request for initial request (Payload is STREAMING constant)
canonical_headers = f'content-type:{content_type}\nhost:{host}\nx-amz-content-sha256:STREAMING-AWS4-HMAC-SHA256-PAYLOAD\nx-amz-date:{amz_date}\nx-amz-decoded-content-length:{file_size}\n'
signed_headers = 'content-type;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length'
canonical_request = f'PUT\n/{bucket_name}/{object_key}\n\n{canonical_headers}\n{signed_headers}\nSTREAMING-AWS4-HMAC-SHA256-PAYLOAD'

print(f"Canonical Request (Initial): {canonical_request}")

# StringToSign for initial request
algorithm = 'AWS4-HMAC-SHA256'
string_to_sign_initial = f'{algorithm}\n{amz_date}\n{credential_scope}\n{hash_sha256(canonical_request)}'

print(f"StringToSign (Initial): {string_to_sign_initial}")

# Calculate the initial signature
initial_signature = hmac.new(signing_key, string_to_sign_initial.encode('utf-8'), hashlib.sha256).hexdigest()

# --- 3. Prepare Headers for the requests.put call ---
headers = {
    'Content-Type': content_type,
    'host': host,
    'x-amz-content-sha256': 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
    'x-amz-date': amz_date,
    'x-amz-decoded-content-length': str(file_size),
    'Authorization': f'{algorithm} Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={initial_signature}',
    'Content-Encoding': 'aws-chunked',
    # IMPORTANT: Do NOT set 'Content-Length' here. requests will handle it
    #            based on the generator using Transfer-Encoding: chunked.
    #            S3 understands this in conjunction with the streaming signature headers.
    #'Expect': '100-continue' # Optional, but can be good practice for PUTs
}

# --- 4. Create the Chunk Generator ---
def chunk_generator(file_path, chunk_size, seed_signature, signing_key, amz_date, scope):
    previous_signature = seed_signature
    empty_hash = hash_sha256('') # Hash of empty string for chunk signing

    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk_data = f.read(chunk_size)
                chunk_data_hash = hash_sha256(chunk_data)

                # StringToSign for the chunk
                string_to_sign_chunk = f'AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{scope}\n{previous_signature}\n{empty_hash}\n{chunk_data_hash}'

                # Sign the chunk
                current_signature = hmac.new(signing_key, string_to_sign_chunk.encode('utf-8'), hashlib.sha256).hexdigest()

                # Format the chunk according to AWS spec
                chunk_header = f'{len(chunk_data):X};chunk-signature={current_signature}\r\n' # hex(size)

                # Yield the formatted chunk (header + data + CRLF)
                yield chunk_header.encode('utf-8')
                yield chunk_data
                yield b'\r\n'

                previous_signature = current_signature # Update for next iteration

                if not chunk_data: # Last chunk was empty or file ended
                    break

            # After loop: Send the final empty chunk
            string_to_sign_final = f'AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{scope}\n{previous_signature}\n{empty_hash}\n{empty_hash}'
            final_signature = hmac.new(signing_key, string_to_sign_final.encode('utf-8'), hashlib.sha256).hexdigest()
            final_chunk = f'0;chunk-signature={final_signature}\r\n\r\n'
            yield final_chunk.encode('utf-8')

    except Exception as e:
        print(f"Error during chunk generation: {e}")
        # Consider how to signal error to requests, maybe raise exception

# --- 5. Make the Request using the Generator ---
print("Starting upload...")
try:
    response = requests.put(
        endpoint,
        headers=headers,
        data=chunk_generator(file_path, chunk_size_bytes, initial_signature, signing_key, amz_date, credential_scope)
        # Let requests handle streaming via the generator
    )
    response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)
    print("Upload successful!")
    print(f"Status Code: {response.status_code}")
    print(f"ETag: {response.headers.get('ETag')}")
    # print(f"Response Body: {response.text}") # Usually empty for successful PUT

except requests.exceptions.RequestException as e:
    print(f"Upload failed: {e}")
    if e.response is not None:
        print(f"Status Code: {e.response.status_code}")
        print(f"Response Body: {e.response.text}")

except Exception as e:
    print(f"An unexpected error occurred: {e}")