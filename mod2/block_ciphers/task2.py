import random
from urllib import parse

from cbc.cbc import encrypt_cbc, decrypt_cbc
from utils.utils import add_padding, strip_padding

KEY: bytes = random.randbytes(16)
IV: bytes = random.randbytes(16)
BLOCK_SIZE = 16

def submit(plaintext: str) -> bytes:
    prepend: str = 'userid=456; userdata='
    append: str = ';session-id=31337'

    text: str = prepend + plaintext + append 

    # actually remove the ; and =
    url_data: bytes = parse.quote(text).encode('utf-8')

    padded_url_data: bytes = add_padding(url_data, BLOCK_SIZE)
    encrypted_text: bytes = encrypt_cbc(padded_url_data, KEY, IV)

    return encrypted_text

def verify(ciphertext: bytes) -> bool:
    search_str: str = ';admin=true;'

    # decrypt the string  
    decrypted_data: bytes = decrypt_cbc(ciphertext, KEY, IV)

    # take off that padding
    unpadded_decrypted_data = strip_padding(decrypted_data)
    
    # In English please
    plain_str: str = unpadded_decrypted_data.decode('utf-8')

    return (search_str in plain_str)

if __name__ == '__main__':
    encrypted_text: bytes = submit(';admin-True;') # close to ;admin-true;


# notes for task 2: bit flipping

# dont flip bits between blocksk
# only flip block within the same block

# if you take the ciphertext byte and xor it with the value of the plaintext and you xor that with the value that you want it to be:
# ciperbit xor plaintext xor what you want it to be

# Hint: you have to understand exactly where the block bounaries are
# print out each individual block
# have to be percice, and helps debugging 

# 


