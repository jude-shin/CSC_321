import random 

from Crypto.Cipher import AES

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

        xor: bytes = bytes(x ^ y for x, y in zip(chunk, prev))

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
