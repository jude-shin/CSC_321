import random 

from Crypto.Cipher import AES

from utils.utils import read_bytes, write_bytes, add_padding, strip_padding, xor_bytes

HEADER_SIZE: int = 54
BLOCK_SIZE: int = 16

def encrypt_ecb(text: bytes, key: bytes) -> bytes:
    cipher = AES.new(key=key, mode=AES.MODE_ECB)

    encrypted_text: bytes = b''
    for i in range(0, len(text), BLOCK_SIZE):
        chunk: bytes = text[i:i+BLOCK_SIZE]
        encrypted_text = encrypted_text + cipher.encrypt(chunk)
    return encrypted_text 

# For testing. I dont see any instructions requiring decryption
def decrypt_ecb(text: bytes, key: bytes) -> bytes:
    # Cipher Function
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    
    # We can use this library
    return cipher.decrypt(text)

def verify_ecb_encryption(text: bytes, encrypted_text: bytes, key: bytes):
    decrypted_text = decrypt_ecb(encrypted_text, key)
    if (text == decrypted_text):
       print("ecb encryption Verified")
    else:
        print("ecb decrypted value did not match original plain text")

def encrypt_bmp_with_ecb(plaintext_file: str):
    text: bytes | None = read_bytes(plaintext_file)

    key: bytes = random.randbytes(BLOCK_SIZE)
    print(f'key: {key}')
    header: bytes = text[:HEADER_SIZE]
    data: bytes = text[HEADER_SIZE:]
    padded_data: bytes = add_padding(data, BLOCK_SIZE)

    encrypted_text: bytes | None = encrypt_ecb(padded_data, key)
    verify_ecb_encryption(padded_data, encrypted_text, key);

    encrypted_text = header + encrypted_text

    bmp_name = plaintext_file.replace('assets/', '').replace('/', '') \
                             .replace('.bmp', '')
    dir_ = 'encryptions/ecb/'

    write_bytes(dir_ + 'encryption_of_' + bmp_name + '.bmp', encrypted_text)
    write_bytes(dir_ + 'key_of_' + bmp_name + '.txt', key)
    
