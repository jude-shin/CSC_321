import random 

from Crypto.Cipher import AES

from utils.utils import read_bytes, write_bytes, add_padding, strip_padding, xor_bytes

HEADER_SIZE: int = 54
BLOCK_SIZE: int = 16

def encrypt_cbc(text: bytes, key: bytes, iv: bytes) -> bytes | None:
    # NOTE: if you specify ECB, then it will probably try to use some input
    # vector every time you call encrypt
    cipher = AES.new(key=key, mode=AES.MODE_ECB)

    encrypted_text: bytes = b''
    prev: bytes = iv
    for i in range(0, len(text), BLOCK_SIZE):
        chunk: bytes = text[i:i+BLOCK_SIZE]

        xor: bytes | None = xor_bytes(chunk, prev)
        if (xor == None):
            return None

        prev = cipher.encrypt(xor) 

        encrypted_text = encrypted_text + prev

    return encrypted_text 

def decrypt_cbc(text: bytes, key: bytes, iv: bytes) -> bytes:
    # Cipher Function
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    
    # We can use this library
    return cipher.decrypt(text)

def encrypt_bmp_with_cbc(plaintext_file: str) -> None:
    text: bytes | None = read_bytes(plaintext_file)
    if (text == None):
        print(f'error reading file: {plaintext_file}\n')
        return None

    # key must be BLOCK_SIZE bytes long (for AES-128)
    key: bytes = random.randbytes(BLOCK_SIZE)
    print(f'key: {key}')

    # iv  must be BLOCK_SIZE bytes long
    iv: bytes = random.randbytes(BLOCK_SIZE)
    print(f'iv: {iv}')
    
    header: bytes = text[:HEADER_SIZE]
    data: bytes = text[HEADER_SIZE:]
    padded_data: bytes = add_padding(data, BLOCK_SIZE)

    encrypted_text: bytes | None = encrypt_cbc(padded_data, key, iv)
    if encrypted_text == None: 
        print(f'Error encrypting data\n')
        return None
    encrypted_text = header + encrypted_text

    write_bytes('encrypted_cbc', encrypted_text)
    write_bytes('key_cbc', key)
    write_bytes('iv_cbc', iv)

