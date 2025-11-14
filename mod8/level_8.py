import base64

ENCODED_SECRET = "3d3d516343746d4d6d6c315669563362"

def reverse_engineer(encoded):
    reversed_b64_bytes = bytes.fromhex(encoded)
    
    reversed_b64_str = reversed_b64_bytes.decode()[::-1]
    
    original_bytes = base64.b64decode(reversed_b64_str)
    
    return original_bytes.decode()

print(reverse_engineer(ENCODED_SECRET))

