import random 

from Crypto.Cipher import AES

from utils.utils import read_bytes, write_bytes, add_padding, strip_padding, xor_bytes

HEADER_SIZE: int = 54
BLOCK_SIZE: int = 16

def encrypt_cbc(text: bytes, key: bytes, iv: bytes) -> bytes:
    # NOTE: if you specify ECB, then it will probably try to use some input
    # vector every time you call encrypt
    cipher = AES.new(key=key, mode=AES.MODE_ECB)

    encrypted_text: bytes = b''
    prev: bytes = iv
    for i in range(0, len(text), BLOCK_SIZE):
        chunk: bytes = text[i:i+BLOCK_SIZE]

        xor: bytes = xor_bytes(chunk, prev)

        prev = cipher.encrypt(xor) 

        encrypted_text = encrypted_text + prev

    return encrypted_text 

def decrypt_cbc(text: bytes, key: bytes, iv: bytes) -> bytes:
    # Cipher Function
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    
    # We can use this library
    return cipher.decrypt(text)

def verify_cbc_encryption(text: bytes, encrypted_text: bytes,
                          key: bytes, iv: bytes):
    decrypted_text = decrypt_cbc(encrypted_text, key, iv)
    if (text == decrypted_text):
       print("cbc encryption Verified")
    else:
        print("cbc decrypted value did not match original plain text")

def encrypt_bmp_with_cbc(plaintext_file: str) -> None:
    text: bytes | None = read_bytes(plaintext_file)

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
    verify_cbc_encryption(padded_data, encrypted_text, key, iv)

    encrypted_text = header + encrypted_text

    bmp_name = plaintext_file.replace('assets/', '').replace('/', '') \
                             .replace('.bmp', '')
    dir_ = 'encryptions/cbc/'

    write_bytes(dir_ + 'encryption_of_' + bmp_name + '.bmp', encrypted_text)

    write_bytes(dir_ + 'key_of_' + bmp_name + '.txt', key)
    write_bytes(dir_ + 'iv_of_' + bmp_name + '.txt', iv)

