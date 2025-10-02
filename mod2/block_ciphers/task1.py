import sys

from cbc.cbc import encrypt_bmp_with_cbc, encrypt_cbc, decrypt_cbc, real_encrypt_cbc
from ecb.ecb import implement_ecb
from utils.utils import add_padding

def task1():
    if len(sys.argv) == 2:
        plaintext_file: str = sys.argv[1]

        # implement_ecb(plaintext_file)
        encrypt_bmp_with_cbc(plaintext_file)

    else:
        print('One cmd line arg required!')


if __name__ == '__main__':
    task1()
