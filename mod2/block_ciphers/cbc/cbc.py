import random 

from Crypto.Cipher import AES

from utils.utils import open_file_as_bytes

def implement_cbc(plaintext_file: str) -> None:
    file = open_file_as_bytes(plaintext_file)
    if (file == None):
        print(f"error opening {plaintext_file}")
        return

    # key must be 16 bytes long (for AES-128)
    key: bytes = random.randbytes(16)

    # iv  must be 16 bytes long
    iv: bytes = random.randbytes(16)
    
    # cipher function
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
     
    print("I have done some cbc")
