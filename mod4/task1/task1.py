import sys
from dataclasses import dataclass
from Crypto.Hash import SHA256
import secrets

def task1(input: bytes):
    hash_obj = SHA256.new(input)
    digest: bytes = hash_obj.digest()
    print(f'[task1] digest: {digest.hex()}') 

if __name__ == '__main__':
    task1(b'Hello, World!')
