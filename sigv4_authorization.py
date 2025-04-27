import datetime
import hashlib
import hmac
import urllib.parse

# --- 辅助函数 ---

def sha256_hash(data):
    """计算数据的 SHA256 哈希值，返回小写十六进制字符串"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()

def hmac_sha256(key, msg):
    """计算 HMAC-SHA256，返回原始 bytes"""
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(msg, str):
        msg = msg.encode('utf-8')
    return hmac.new(key, msg, hashlib.sha256).digest()

# --- SigV4 签名主函数 ---

def calculate_sigv4_authorization(
    access_key: str,
    secret_key: str,
    http_method: str,         # 大写 HTTP 方法, e.g., 'GET', 'PUT'
    service: str,             # 服务名称, e.g., 's3'
    region: str,              # AWS 区域, e.g., 'us-east-1'
    host: str,                # 目标主机名, e.g., 'mybucket.s3.amazonaws.com' or '172.20.123.123'
    path: str,                # 请求的绝对路径, e.g., '/', '/myobject.txt'
    query_params: dict,       # 查询参数字典, e.g., {'delimiter': '/', 'max-keys': '1000'}
    headers: dict,            # 请求头字典 (键应为小写), e.g., {'content-type': 'text/plain'}
    payload: bytes = b''      # 请求体 (bytes), 对于 GET 通常是空 b''
    ):
    """
    计算 AWS Signature Version 4 的 Authorization header。

    返回:
        一个元组 (authorization_header, amz_date, signed_headers_str)
        - authorization_header: 计算得到的 Authorization 头部字符串
        - amz_date: 用于签名的 x-amz-date 时间戳 (YYYYMMDDTHHMMSSZ)
        - signed_headers_str: 参与签名的头部名称列表字符串 (分号分隔)
    """

    # --- 准备时间和日期戳 ---
    now = datetime.datetime.utcnow()
    amz_date = '20250421T055442Z' # now.strftime('%Y%m%dT%H%M%SZ') # ISO8601 格式 Z 表示 UTC
    date_stamp = now.strftime('%Y%m%d')       # YYYYMMDD 格式

    # --- 规范化和准备头部 ---
    # 确保 host 和 x-amz-date 头存在 (键使用小写)
    headers_lower = {k.lower(): v for k, v in headers.items()} # 确保键是小写
    if 'host' not in headers_lower:
        headers_lower['host'] = host
    if 'x-amz-date' not in headers_lower:
         headers_lower['x-amz-date'] = amz_date # 将生成的日期  加入头部

    # 对头部按 key 排序
    sorted_header_keys = sorted(headers_lower.keys())

    # 构建 CanonicalHeaders 和 SignedHeaders
    canonical_headers_parts = []
    signed_headers_parts = []
    for key in sorted_header_keys:
        # SigV4 要求对 header value 前后的空格进行修剪
        # 并且将连续的空格压缩成一个 (这里简化为 strip)
        value = str(headers_lower[key]).strip() # 简单修剪
        canonical_headers_parts.append(f"{key}:{value}")
        signed_headers_parts.append(key)

    canonical_headers = '\n'.join(canonical_headers_parts) + '\n'
    signed_headers_str = ';'.join(signed_headers_parts)

    # --- 计算 Payload 哈希 ---
    # 对于 GET 请求或其他无 Body 的请求，payload 是空字符串 b''
    # 对于有 Body 的请求，需要计算实际 Body 的 SHA256 哈希
    # 注意：对于 S3 流式上传等，可能使用 'UNSIGNED-PAYLOAD'
    hashed_payload = sha256_hash(payload)

    # --- 规范化 URI 和查询字符串 ---
    # 对路径进行 URI 编码 (但 '/' 不编码)
    canonical_uri = urllib.parse.quote(path, safe='/~')
    if not canonical_uri.startswith('/'):
        canonical_uri = '/' + canonical_uri # 确保以 / 开头

    # 对查询参数按 key 排序并进行 URL 编码
    sorted_query_params = sorted(query_params.items())
    canonical_query_string = urllib.parse.urlencode(sorted_query_params, quote_via=urllib.parse.quote)


    # --- 步骤 1: 创建规范请求 (Canonical Request) ---
    canonical_request = (
        f"{http_method}\n"
        f"{canonical_uri}\n"
        f"{canonical_query_string}\n"
        f"{canonical_headers}\n"
        f"{signed_headers_str}\n"
        f"{hashed_payload}"
    )

    print("--- Debug: Canonical Request ---")
    print(repr(canonical_request))
    print("-----------------------------")

    # --- 步骤 2: 创建待签字符串 (StringToSign) ---
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    hashed_canonical_request = sha256_hash(canonical_request)

    string_to_sign = (
        f"{algorithm}\n"
        f"{amz_date}\n"
        f"{credential_scope}\n"
        f"{hashed_canonical_request}"
    )

    print("--- Debug: StringToSign ---")
    print(repr(string_to_sign))    
    print("--------------------------")

    # --- 步骤 3: 计算签名 ---
    #   3a: 派生签名密钥 (Signing Key)
    k_date = hmac_sha256(f"AWS4{secret_key}", date_stamp)
    k_region = hmac_sha256(k_date, region)
    k_service = hmac_sha256(k_region, service)
    k_signing = hmac_sha256(k_service, 'aws4_request')

    #   3b: 计算最终签名
    signature_bytes = hmac_sha256(k_signing, string_to_sign)
    signature_hex = signature_bytes.hex() # 转换为小写十六进制

    print(f"--- Debug: Signature (Hex) ---\n{signature_hex}\n---------------------------")


    # --- 步骤 4: 构建 Authorization Header ---
    authorization_header = (
        f"{algorithm} "
        f"Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers_str}, "
        f"Signature={signature_hex}"
    )

    return authorization_header, amz_date, signed_headers_str, hashed_payload


# --- 示例用法 ---
if __name__ == "__main__":
    # --- 输入配置 (需要根据你的实际情况修改) ---
    access_key = "MAKI9JGZYIXE6ARQCKZ1"  # 你的 Access Key
    secret_key = "dYdcCs9y1CmKTcvwtZCWEERdK8i3S8hkGh83aYo7" # 你的 Secret Key
    service_name = "s3"
    # 重要：确认你的 S3 兼容存储使用的区域标识符
    # 如果不确定，'us-east-1' 是一个常见的默认值，但最好查阅文档
    region_name = "us-east-1"
    endpoint_host = "172.20.123.123" # 你的服务器地址
    http_method = "GET"              # 请求方法

    # 示例 1: 类似 GET / 的请求
    request_path = "/"
    request_query_params = {} # 无查询参数
    request_payload = b''     # GET 请求无 payload
    request_headers = {       # 需要包含 host, x-amz-date 会自动添加
        # 'user-agent': 'My Python Client 1.0' # 可选，但会参与签名
    }


    print(f"Calculating SigV4 for: {http_method} {endpoint_host}{request_path}")
    print(f"Query Params: {request_query_params}")
    print("-" * 20)

    # --- 调用签名函数 ---
    try:
        auth_header, req_amz_date, signed_hdrs, hashed_payload = calculate_sigv4_authorization(
            access_key=access_key,
            secret_key=secret_key,
            http_method=http_method,
            service=service_name,
            region=region_name,
            host=endpoint_host,
            path=request_path,
            query_params=request_query_params,
            headers=request_headers, # 传入初始 headers
            payload=request_payload
        )

        print("\n--- Results ---")
        print(f"x-amz-date to send: {req_amz_date}")
        print(f"SignedHeaders to send: {signed_hdrs}") # 确认哪些头参与了签名
        print(f"Authorization header to send:\n{auth_header}")
        
    except Exception as e:
        pass