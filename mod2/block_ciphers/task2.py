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
    prepend: str = 'userid=456;userdata='
    append: str = ';session-id=31337'

    full_text: str = prepend + text + append 
    
    url_data: bytes = full_text.encode('utf-8')

    padded_url_data: bytes = add_padding(url_data, BLOCK_SIZE)
    encrypted_text: bytes = encrypt_cbc(padded_url_data, KEY, IV)

    return encrypted_text

def verify(ciphertext: bytes) -> bool:
    search_str: str = ';admin=true;'

    # decrypt the string  
    decrypted_data: bytes = decrypt_cbc(ciphertext, KEY, IV)

    # In English please
    plain_str: str = parse.unquote(decrypted_data)

    return (search_str in plain_str)


if __name__ == '__main__':
    # The byte we want to flip is at position 21
    text: str = ';ydmin=true'
    mod_char: str = 'y'
    target_char: str = 'a'
    i: int = 21
    ti: int = i - BLOCK_SIZE

    encrypted_text = submit(text)
    decrypted_text = decrypt_cbc(encrypted_text, KEY, IV)

    # ===============================================

    xor: int = ord(mod_char) ^ ord(target_char)

    modified_byte: bytes = (encrypted_text[ti] ^ xor).to_bytes(1, 'big')
    modified_encrypted_text: bytes = encrypted_text[:ti] + (modified_byte) + encrypted_text[ti+1:]

    print(f'Encrypted Text  : {encrypted_text}')
    print(f'Modified Text   : {modified_encrypted_text}')

    # ===============================================
    decrypted_mod: bytes = decrypt_cbc(modified_encrypted_text, KEY, IV)
    print(f'decrypted_text : {parse.unquote(decrypted_text)}')
    print(f'decrypted_mod  : {parse.unquote(decrypted_mod)}')
    # ===============================================

    print(f'Verification result: {verify(modified_encrypted_text)}')
    print(f'Verification result: {verify(encrypted_text)}')




