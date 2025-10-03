import random
from urllib import parse

from cbc.cbc import encrypt_cbc, decrypt_cbc
from utils.utils import add_padding, strip_padding, xor_bytes

BLOCK_SIZE = 16
# just for testing so that we get deterministic test results
# we can analyze
KEY: bytes = add_padding(b'key', BLOCK_SIZE)
IV: bytes = add_padding(b'iv', BLOCK_SIZE)
# KEY: bytes = random.randbytes(BLOCK_SIZE)
# IV: bytes = random.randbytes(BLOCK_SIZE)


def submit(text: str) -> bytes:
    # prepend: str = 'userid=456;userdata='
    # append: str = ';session-id=31337'

    # full_text: str = prepend + text + append 

    
    full_text: str = text


    # TODO: do we actually remove the ; and = ?
    url_data: bytes = parse.quote(full_text).encode('utf-8')

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
    # The byte we want to flip is at position 30
    text: str = ';ydmin-true'
    target_char: str = 'a'
    i: int = 21
    ti: int = i - BLOCK_SIZE

    prepend: str = 'userid=456;userdata='
    append: str = ';session-id=31337'
    full_text: str = prepend + text + append 
    print(f'full_text: {full_text}')
    print(f'target_char: {full_text[i]}')

    print(f'P1: {full_text[:BLOCK_SIZE]}')
    print(f'P2: {full_text[BLOCK_SIZE:BLOCK_SIZE*2]}')
    print(f'P2: {full_text[BLOCK_SIZE*2:BLOCK_SIZE*3]}')

    encrypted_text: bytes = submit(full_text) # close to ;admin-true
    decrypted_text: bytes = decrypt_cbc(encrypted_text, KEY, IV)
    
    # ===============================================

    xor: int = ord(full_text[i]) ^ ord(target_char)

    modified_byte: bytes = (encrypted_text[ti] ^ xor).to_bytes(1, 'big')
    modified_encrypted_text: bytes = encrypted_text[:ti] + (modified_byte) + encrypted_text[ti+1:]

    print(f'Encrypted Text  : {encrypted_text}')
    print(f'Modified Text   : {modified_encrypted_text}')
    # ===============================================
    decrypted_mod: bytes = decrypt_cbc(modified_encrypted_text, KEY, IV)
    print(f'decrypted_text : {parse.unquote(decrypted_text)}')
    print(f'decrypted_mod  : {parse.unquote(decrypted_mod)}')
    # ===============================================

    # print(f'Verification result: {verify(modified_encrypted_text)}')




