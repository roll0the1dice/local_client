import hashlib
import hmac
import datetime
import os
from typing import Dict, Optional, Union
from urllib.parse import quote
import requests

class AWSV4ChunkedUploader:
    def __init__(
        self,
        access_key: str,
        secret_key: str,
        region: str,
        service: str,
        host: str,
        chunk_size: int = 64 * 1024  # 64KB chunks by default
    ):
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.service = service
        self.host = host
        self.chunk_size = chunk_size
        
    def sign(self, key: bytes, msg: Union[str, bytes]) -> bytes:
        """Calculate HMAC-SHA256."""
        if isinstance(msg, str):
            msg = msg.encode('utf-8')
        return hmac.new(key, msg, hashlib.sha256).digest()
    
    def get_signature_key(self, date_stamp: str, region_name: str, service_name: str) -> bytes:
        """Generate the signing key for AWS Signature V4."""
        k_date = self.sign(f'AWS4{self.secret_key}'.encode('utf-8'), date_stamp)
        k_region = self.sign(k_date, region_name)
        k_service = self.sign(k_region, service_name)
        k_signing = self.sign(k_service, 'aws4_request')
        return k_signing
    
    def create_canonical_request(
        self,
        method: str,
        canonical_uri: str,
        query_string: str,
        headers: Dict[str, str],
        payload_hash: str
    ) -> str:
        """Create canonical request for AWS Signature V4."""
        # Convert all header keys to lowercase
        lowercase_headers = {k.lower(): v for k, v in headers.items()}
        
        # Define the exact order of headers as per AWS documentation
        header_order = [
            'content-encoding',
            'host',
            'x-amz-content-sha256',
            'x-amz-date',
            'x-amz-decoded-content-length',
            'x-amz-storage-class',
            'x-amz-trailer'
        ]
        
        # Create canonical headers in exact order
        canonical_headers = '\n'.join([
            f"{k}:{lowercase_headers[k]}"
            for k in header_order
            if k in lowercase_headers
        ]) + '\n\n'  # Add extra newline as per AWS documentation
        
        # Create signed headers in exact order
        signed_headers = ';'.join([
            k
            for k in header_order
            if k in lowercase_headers
        ])
        
        # Use the same payload hash as in x-amz-content-sha256 header
        final_payload_hash = lowercase_headers.get('x-amz-content-sha256', payload_hash)
        
        # Create canonical request with exact format
        canonical_request = '\n'.join([
            method,
            canonical_uri,
            query_string,
            canonical_headers,
            signed_headers,
            final_payload_hash
        ])
        
        print("Canonical Request:")
        print(canonical_request)
        print("---")
        
        # Calculate and print the hash of canonical request
        hashed_canonical_request = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        print("Hashed Canonical Request:")
        print(hashed_canonical_request)
        print("---")
        
        return canonical_request
    
    def get_authorization_header(
        self,
        method: str,
        canonical_uri: str,
        query_string: str,
        headers: Dict[str, str],
        payload_hash: str,
        timestamp: Optional[datetime.datetime] = None
    ) -> str:
        """Generate the Authorization header for AWS Signature V4."""
        if timestamp is None:
            timestamp = datetime.datetime.utcnow()
        
        amz_date = timestamp.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = timestamp.strftime('%Y%m%d')
        
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = f"{date_stamp}/{self.region}/{self.service}/aws4_request"
        
        # Convert all header keys to lowercase
        lowercase_headers = {k.lower(): v for k, v in headers.items()}
        
        # Create canonical headers
        canonical_headers = '\n'.join([
            f"{k}:{v}"
            for k, v in sorted(lowercase_headers.items())
        ]) + '\n'
        
        # Create signed headers
        signed_headers = ';'.join([
            k
            for k in sorted(lowercase_headers.keys())
        ])
        
        # Create canonical request
        canonical_request = '\n'.join([
            method,
            canonical_uri,
            query_string,
            canonical_headers,
            signed_headers,
            payload_hash
        ])

        print(canonical_request)

        hashed_canonical_request = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        
        # Create string to sign
        string_to_sign = '\n'.join([
            algorithm,
            amz_date,
            credential_scope,
            hashed_canonical_request
        ])
        
        # Calculate signature
        signing_key = self.get_signature_key(date_stamp, self.region, self.service)
        signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        
        # Create authorization header
        return (
            f"{algorithm} "
            f"Credential={self.access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature}"
        )
    
    def calculate_chunk_signature(
        self,
        previous_signature: str,
        date: str,
        credential_scope: str,
        chunk_data: bytes
    ) -> str:
        
        hashed_payload =  hashlib.sha256(chunk_data).hexdigest()

        hashed_empty_string = hashlib.sha256(b'').hexdigest()

        """Calculate signature for a chunk in a chunked upload."""
        string_to_sign = '\n'.join([
            'AWS4-HMAC-SHA256-PAYLOAD',
            date,
            credential_scope,
            previous_signature,
            hashed_empty_string,  # empty string hash
            hashed_payload
        ])
        
        signing_key = self.get_signature_key(
            date.split('T')[0],
            self.region,
            self.service
        )
        
        return hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    
    def calculate_chunk_metadata_size(self, chunk_size):
        # Convert chunk size to hex and get actual length
        size_hex = hex(chunk_size)[2:]
        hex_length = len(size_hex)
        # size-hex + ; + chunk-signature= + signature (64) + \r\n
        metadata_size = hex_length + 1 + len('chunk-signature=') + 64 + 2
        print(f"Chunk size {chunk_size} (0x{size_hex}): metadata size = {metadata_size}")
        return metadata_size
    
    def parse_aws_timestamp(self, aws_timestamp: str) -> datetime.datetime:
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

    def upload_file(self, file_path: str, bucket: str, key: str) -> None:
        """Upload a file using chunked upload with AWS Signature V4."""
        method = 'PUT'
        url = f'https://{self.host}/{bucket}/{quote(key)}'
        canonical_uri = f'/{bucket}/{quote(key)}'
        query_string = ''
        
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Calculate chunk sizes
        chunk_sizes = []
        remaining_size = file_size
        while remaining_size > 0:
            current_chunk_size = min(remaining_size, self.chunk_size)
            chunk_sizes.append(current_chunk_size)
            remaining_size -= current_chunk_size
        
        total_chunks = len(chunk_sizes)
        
        # Calculate total metadata size
        chunk_metadata_sizes = [
            self.calculate_chunk_metadata_size(size) + 2  # +2 for chunk separator \r\n
            for size in chunk_sizes
        ]
        total_metadata_size = sum(chunk_metadata_sizes)
        
        # Add final empty chunk metadata and its separator
        final_chunk_metadata = self.calculate_chunk_metadata_size(0) + 2  # +2 for final \r\n
        
        # Calculate total content length
        total_content_length = (
            file_size +  # Original file content
            total_metadata_size +  # All chunks metadata and separators
            final_chunk_metadata  # Final empty chunk and its separator
        )
        
        # Prepare initial headers
        timestamp = self.parse_aws_timestamp('20130524T000000Z')
        amz_date = '20130524T000000Z'
        date_stamp = '20130524'
        
        headers = {
            'Host': self.host,
            'x-amz-date': amz_date,
            'x-amz-content-sha256': 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER',
            'Content-Encoding': 'aws-chunked',
            #'Content-Length': str(total_content_length),
            'x-amz-storage-class': 'REDUCED_REDUNDANCY',
            'x-amz-decoded-content-length': str(file_size),
            'x-amz-trailer': 'x-amz-checksum-crc32c'
        }
        
        # Get initial authorization header
        authorization = self.get_authorization_header(
            method,
            canonical_uri,
            query_string,
            headers,
            'STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER',
            timestamp
        )
        
        headers['Authorization'] = authorization
        
        print(f"Initial Headers:")
        for k, v in headers.items():
            print(f"{k}: {v}")
        
        # Process file in chunks
        credential_scope = f"{date_stamp}/{self.region}/{self.service}/aws4_request"
        previous_signature = authorization.split('Signature=')[1]
        
        with open(file_path, 'rb') as f:
            chunk_number = 0
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                
                # Calculate chunk signature
                chunk_signature = self.calculate_chunk_signature(
                    previous_signature,
                    amz_date,
                    credential_scope,
                    chunk
                )
                
                chunk_size_hex = hex(len(chunk))[2:]
                chunk_metadata = f"{chunk_size_hex};chunk-signature={chunk_signature}\r\n"
                
                print(f"\nChunk {chunk_number + 1}:")
                print(f"Chunk Size: {len(chunk)} bytes")
                print(f"Chunk Signature: {chunk_signature}")
                print(f"Chunk Metadata: {chunk_metadata}")
                
                # Convert metadata to bytes and concatenate with chunk data
                chunk_data = chunk_metadata.encode('utf-8') + chunk + b'\r\n'
                
                # Make request with the chunk
                #self.make_request(method, url, headers, chunk_data)
                
                previous_signature = chunk_signature
                chunk_number += 1
            
            # Send final empty chunk to signal end of transmission
            final_chunk_signature = self.calculate_chunk_signature(
                previous_signature,
                amz_date,
                credential_scope,
                b''
            )
            
            final_metadata = f"0;chunk-signature={final_chunk_signature}\r\n"
            print("\nFinal empty chunk:")
            print(f"Chunk Signature: {final_chunk_signature}")
            print(f"Chunk Metadata: {final_metadata}")
            
            # Convert final metadata to bytes and send
            final_data = final_metadata.encode('utf-8') + b'\r\n'
            #self.make_request(method, url, headers, final_data)

    def make_request(self, method: str, url: str, headers: Dict[str, str], data: Optional[bytes] = None):
        """Make an HTTP request with retry logic."""
        try:
            print(f"\nMaking {method} request to {url}")
            print("Request headers:")
            for k, v in headers.items():
                print(f"{k}: {v}")
            
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                stream=True
            )
            
            
            response.raise_for_status()
            
            print(response.text)

        except requests.exceptions.RequestException as e:
            print(f"Request failed....")
            print(f"Error: {str(e)}")
    

def main():
    # Example usage
    uploader = AWSV4ChunkedUploader(
        access_key='AKIAIOSFODNN7EXAMPLE',
        secret_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        region='us-east-1',
        service='s3',
        host='s3.amazonaws.com'
    )
    
    # Create a sample file
    with open('test_file.txt', 'w') as f:
        f.write('a' * 66560)  # Create a 65KB file (65 * 1024 = 66560 bytes)
    
    try:
        uploader.upload_file(
            file_path='test_file.txt',
            bucket='examplebucket',
            key='chunkObject.txt'
        )
    finally:
        # Clean up test file
        os.remove('test_file.txt')

if __name__ == '__main__':
    main() 