import hashlib
import hmac
import datetime
import os
from typing import Dict, Optional, Union
from urllib.parse import quote

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
        canonical_headers = '\n'.join([
            f"{k.lower()}:{v}"
            for k, v in sorted(headers.items())
        ]) + '\n'
        
        signed_headers = ';'.join([
            k.lower()
            for k in sorted(headers.keys())
        ])
        
        return '\n'.join([
            method,
            canonical_uri,
            query_string,
            canonical_headers,
            signed_headers,
            payload_hash
        ])
    
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
        
        amz_date = '20130524T000000Z' # timestamp.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = '20130524' # timestamp.strftime('%Y%m%d')
        
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = f"{date_stamp}/{self.region}/{self.service}/aws4_request"
        
        canonical_request = self.create_canonical_request(
            method,
            canonical_uri,
            query_string,
            headers,
            payload_hash
        )
        
        string_to_sign = '\n'.join([
            algorithm,
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        ])
        
        signing_key = self.get_signature_key(date_stamp, self.region, self.service)
        signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
        
        return (
            f"{algorithm} "
            f"Credential={self.access_key}/{credential_scope}, "
            f"SignedHeaders={';'.join(sorted([k.lower() for k in headers.keys()]))},"
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
    
    def upload_file(self, file_path: str, bucket: str, key: str) -> None:
        """Upload a file using chunked upload with AWS Signature V4."""
        method = 'PUT'
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
        
        print("\nDetailed size calculation:")
        print(f"File size: {file_size} bytes")
        print(f"Total chunks: {total_chunks}")
        print(f"Chunk sizes: {chunk_sizes}")
        print(f"Chunk metadata sizes: {chunk_metadata_sizes}")
        print(f"Total metadata size: {total_metadata_size} bytes")
        print(f"Final chunk metadata size: {final_chunk_metadata} bytes")
        print(f"Total content length: {total_content_length} bytes")
        
        # Prepare initial headers
        timestamp = datetime.datetime.utcnow()
        amz_date = '20130524T000000Z' # timestamp.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = '20130524' # timestamp.strftime('%Y%m%d')
        
        headers = {
            'Host': self.host,
            'x-amz-date': amz_date,
            'x-amz-content-sha256': 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
            'Content-Encoding': 'aws-chunked',
            'Content-Length': str(total_content_length),
            'x-amz-storage-class': 'REDUCED_REDUNDANCY',
            'x-amz-decoded-content-length': str(file_size)
        }
        
        # Get initial authorization header
        authorization = self.get_authorization_header(
            method,
            canonical_uri,
            query_string,
            headers,
            'STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
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
                
                # In a real implementation, you would send:
                # 1. chunk_metadata
                # 2. chunk
                # 3. \r\n
                
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