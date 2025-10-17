import sys
from dataclasses import dataclass
from Crypto.Hash import SHA256
import secrets
import random 

# Hashes an arbitrary input and prints the digest to the screen in hexadecimal
# format.
def part_a(input: bytes) -> bytes:
    print('Task1 Part A\n')

    hash_obj = SHA256.new(input)
    digest: bytes = hash_obj.digest()
    print(f'[task1] digest: {digest.hex()}') 
    
    return digest

# Takes a string, turns it into bytes, gets a random string that has a hamming
# distance of exactly 1 bit, and returns the SHA256 values of both of those
def part_b(original: str) -> tuple[bytes, bytes]:
    print('Task1 Part B\n')

    # Turn the string of interest into bytes
    original_bytes: bytes = original.encode('utf-8')

    # Get a random string whos hamming distance is exactly 1 bit
    hammed: bytes = get_single_hamm(original_bytes)
    
    hashed_original: bytes = part_a(original_bytes)
    hammed_original: bytes = part_a(hammed)

    return (hashed_original, hammed_original)


# Randomly flips one bit of an arbitrary length byte string, 
# resulting in the hamming distance of 1.
def get_single_hamm(input: bytes) -> bytes:
    byte_array: bytearray = bytearray(input)
    bit_count: int = len(byte_array) * 8

    bit_index: int = random.randrange(bit_count)
    byte_index: int = bit_index//8
    inner_bit_index: int = bit_index%8

    byte_array[byte_index] ^= (1 << inner_bit_index)
    return(bytes(byte_array))

#
def part_c():
    pass


if __name__ == '__main__':
    # Part A
    part_a(b'Hello, World!')

    # Part B 
    str1: str = 'Hello'
    str2: str = 'beautiful'
    str3: str = 'world!'

    hashed_str1_original, hashed_str1_hammed = part_b(str1)
    hashed_str2_original, hashed_str2_hammed = part_b(str2)
    hashed_str3_original, hashed_str3_hammed = part_b(str3)

    # Part C


    

    



