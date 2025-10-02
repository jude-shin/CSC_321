import random 
import sys 

from Crypto.Cipher import AES

from utils.utils import read_bytes, write_bytes, add_padding, strip_padding

HEADER_SIZE: int = 54
BLOCK_SIZE: int = 128 

def implement_cbc(plaintext_file: str) -> None:
    plaintext: bytes | None = read_bytes(plaintext_file)
    if (plaintext == None):
        print(f'error reading file: {plaintext_file}')
        return

    # key must be 16 bytes long (for AES-128)
    key: bytes = random.randbytes(16)
    print(f'key: {key}')

    # iv  must be 16 bytes long
    iv: bytes = random.randbytes(16)
    print(f'iv: {iv}')
    
    encrypted_text: bytes = encrypt_cbc(plaintext, key, iv)

    if (write_bytes('encrypted', encrypted_text) == None):
        print(f'error writing file')
        return

    if (write_bytes('key', key) == None):
        print(f'error writing file')
        return

    if (write_bytes('iv', iv) == None):
        print(f'error writing file')
        return

def encrypt_cbc(text: bytes, key: bytes, iv: bytes) -> bytes:
    header: bytes = text[:HEADER_SIZE]
    data: bytes = text[HEADER_SIZE:]

    padded_data: bytes = add_padding(data, BLOCK_SIZE)

    # Cipher Function
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)

    # encrypt BLOCK_SIZE at a time, each time adding it to the encrypted_text
    encrypted_text: bytes = header
    for i in range(int(len(padded_data)/BLOCK_SIZE)):
        data_chunk: bytes = padded_data[(i*BLOCK_SIZE):((i+1)*BLOCK_SIZE)]
        encrypted_chunk: bytes = cipher.encrypt(data_chunk)
        encrypted_text = encrypted_text + encrypted_chunk

    return encrypted_text 
