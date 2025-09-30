from Crypto.Cipher import AES

from utils.utils import generate_random_key

def implement_cbc(plaintext_file: str, block_size: int): 
    # iv  must be 16 bytes long
    print("I have done some cbc")
