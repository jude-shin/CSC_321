import sys

from cbc.cbc import implement_cbc
from ecb.ecb import implement_ecb

BLOCK_SIZE: int = 128

def task1():
    if len(sys.argv) == 1:
        plaintext_file: str = sys.argv[1]

        # implement_ecb(plaintext_file, BLOCK_SIZE)
        implement_cbc(plaintext_file, BLOCK_SIZE)

    else:
        print("no command arguments provided")


if __name__ == "__main__":
    task1()
