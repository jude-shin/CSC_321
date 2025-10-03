def read_bytes(filename: str) -> bytes:
    with open(filename, 'rb') as f:
        return f.read()

def write_bytes(filename: str, text: bytes) -> None:
    with open(filename, 'wb+') as f:
        f.write(text)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise Exception('a and b must be of same length')
    
    return bytes(x ^ y for x, y in zip(a, b))

# pad text bytes with pkcs#7 padding
def add_padding(text: bytes, block_size: int) -> bytes:
    # Get the remainder that is needed to become a multiple of block_size
    k: int = block_size - len(text)%block_size

    # k(byte) will be repeated k times
    single_byte: bytes = k.to_bytes(1, 'big')
    padding: bytes = single_byte * k

    # Append the padding to the end of the text 
    return text + padding 

# remove a padded text bytes with pkcs#7 padding
def strip_padding(text: bytes) -> bytes:
    # Read the last block (should be an int)
    k: int = text[-1]

    # If the number that are in the last k bytes does not match up, then there
    # was no padding (or a padding of 0)
    for i in range(k):
        if (k != text[-(i+1)]):
            return text 

    # Remove the last k bytes in text 
    return text[:-k]
