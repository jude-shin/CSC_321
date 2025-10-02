import sys

from cbc.cbc import encrypt_bmp_with_cbc, encrypt_cbc, decrypt_cbc, real_encrypt_cbc
from ecb.ecb import implement_ecb
from utils.utils import add_padding

def task1():
    if len(sys.argv) == 2:
        plaintext_file: str = sys.argv[1]

        # implement_ecb(plaintext_file)
        # encrypt_bmp_with_cbc(plaintext_file)
    

        text: bytes = b'hello there this should be many many blocks long'
        padded_text: bytes = add_padding(text, 16)


        key: bytes = add_padding(b'key', 16)
        iv: bytes = add_padding(b'iv', 16)
        print(f'key: {key} \niv: {iv}')


        encrypted_text: bytes | None = encrypt_cbc(padded_text, key, iv)
        if (encrypted_text == None):
            print('error')
            return

        decrypted_text: bytes = decrypt_cbc(encrypted_text, key, iv)

        # print(f'original      : {padded_text}\n')
        # print(f'encrypted     : {encrypted_text}')
        # print(f'decrypted     : {decrypted_text}\n')


        if (padded_text== decrypted_text):
            print(f'YAAAAAAAAAAAAAAAAAAA they match!')


    else:
        print('One cmd line arg required!')


if __name__ == '__main__':
    task1()
