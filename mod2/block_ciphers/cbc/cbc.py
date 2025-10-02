import random 
import sys 

from Crypto.Cipher import AES

from utils.utils import open_file_as_bytes, add_padding, strip_padding

def implement_cbc(plaintext_file: str) -> None:
    sys.set_int_max_str_digits(10000)

    plaintext: bytes | None = open_file_as_bytes(plaintext_file)
    if (plaintext == None):
        print(f'error opening {plaintext_file}')
        return
    # print(f'plaintext_message: {plaintext}')

    # key must be 16 bytes long (for AES-128)
    key: bytes = random.randbytes(16)
    print(f'key: {key}')

    # iv  must be 16 bytes long
    iv: bytes = random.randbytes(16)
    print(f'iv: {iv}')
    
    padded_plaintext: bytes = add_padding(plaintext, 128)

    # cipher function
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
     
    print('Yay, cbc completed!\n')


def block_cipher(plaintext_message : bytes) -> bytes:
    return plaintext_message 
