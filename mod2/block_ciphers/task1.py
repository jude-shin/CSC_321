import sys

from cbc.cbc import encrypt_bmp_with_cbc
from ecb.ecb import encrypt_bmp_with_ecb

if __name__ == '__main__':
    if len(sys.argv) == 2:
        plaintext_file: str = sys.argv[1]

        encrypt_bmp_with_ecb(plaintext_file)
        encrypt_bmp_with_cbc(plaintext_file)

    else:
        print('One cmd line arg required!')
