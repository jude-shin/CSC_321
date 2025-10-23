import random
import time
import os

from Crypto.Hash import SHA256
from datetime import timedelta

import matplotlib.pyplot as plt
import numpy as np


# Hashes an arbitrary input and prints the digest to the screen in hexadecimal
# format.
def part_a(input: bytes, hash_obj: SHA256.SHA256Hash, verbose: bool = True) -> bytes:
    hash_obj.update(input)
    digest: bytes = hash_obj.digest()
    if verbose: 
        print(f'[task1] digest: {digest.hex()}') 
    
    return digest

# Takes a string, turns it into bytes, gets a random string that has a hamming
# distance of exactly 1 bit, and returns the SHA256 values of both of those
def part_b(original: str, hash_obj: SHA256.SHA256Hash) -> tuple[bytes, bytes]:

    # Turn the string of interest into bytes
    original_bytes: bytes = original.encode('utf-8')

    # Get a random string whos hamming distance is exactly 1 bit
    hammed: bytes = get_single_hamm(original_bytes)
    
    hashed_original: bytes = part_a(original_bytes, hash_obj)
    hammed_original: bytes = part_a(hammed, hash_obj)

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

# Truncates a digest to a particular
# to a particular domain (in bits)
def part_c(digest: bytes, trunc_len: int) -> bytes:
    # Bytes needed to remove from the digest 
    # working with bytearrays are easier
    truncate_bytes_count: int = trunc_len // 8
    # Remaining fine tuning bits to "remove"
    truncate_bits_count: int = trunc_len % 8

    # Take the first n bytes
    truncated_digest: bytearray = bytearray(digest[:truncate_bytes_count])

    # Bitshift the remaining bits from the digest and tack it on the end of the
    # truncated_digest
    if truncate_bits_count > 0:
        # Note that the remainder of the 'byte' is going to be just zeros
        mask: float = (0xFF << (8-truncate_bits_count)) & 0xFF
        last_byte: float = digest[truncate_bytes_count] & mask
        truncated_digest.append(last_byte)

    return bytes(truncated_digest)

# Takes advantage of the birthday problem 
def process_graphs(hash_obj: SHA256.SHA256Hash) -> None:
    asset_path: str = './assets' 
    dvc_path: str = os.path.join(asset_path, 'digest_sizes_v_collision_times.png')
    dvi_path: str = os.path.join(asset_path, 'digest_sizes_v_imput_count.png') 

    digest_sizes: list[int] = list(range(8, 51, 2))
    collision_times: list[float] = [] # in seconds
    input_count: list[int] = [] # in seconds

    # {truncated digest: message}
    seen: dict[bytes, bytes] = {}

    # =======================================================================

    for b in digest_sizes:
        start_time: float = time.perf_counter()
        j: int = 0

        while True:
            j += 1
           
            # changing the length of this inital input vector did not do that
            # much to help with the time
            m0_bytes: bytes = os.urandom(10)
            m0_digest: bytes = part_a(m0_bytes, hash_obj, False)
            m0_truncated_digest: bytes = part_c(m0_digest, b)
            
            if m0_truncated_digest in seen and m0_bytes != seen[m0_truncated_digest]:
                print(f'[{b}]Collision found at iteration {j} with digest: {m0_truncated_digest}')
                print(f'[{b}]message_0: {m0_bytes}')
                print(f'[{b}]message_1: {seen[m0_truncated_digest]}')
                print('-------------------------\n')

                elapsed_time: float = time.perf_counter() - start_time

                collision_times.append(elapsed_time)
                input_count.append(j)

                break # break the while loop
            else:
                # add it to the list of seen digests
                seen.update({m0_truncated_digest: m0_bytes})


    print(f'digest_sizes: {digest_sizes}')
    print(f'collision_times: {collision_times}')
    print(f'input_count: {input_count}')

    plt.plot(digest_sizes, collision_times)
    plt.xlabel('Digest Sizes (bits)')
    plt.ylabel('Collision Times(seconds)')
    plt.title('Digest Sizes v Collision Times')

    plt.savefig(dvc_path, bbox_inches='tight')
    # plt.show()

    plt.clf()

    plt.plot(digest_sizes, input_count)
    plt.xlabel('Digest Sizes (bits)')
    plt.ylabel('Input (int)')
    plt.title('Digest Sizes v Input Count')

    plt.savefig(dvi_path, bbox_inches='tight')
    # plt.show()

    plt.clf()


if __name__ == '__main__':
    hash_obj: SHA256.SHA256Hash = SHA256.new()

    # Part A
    print('\n--- Task1 Part A ---\n')

    foo_a: bytes = 'Hello, World!'.encode('utf-8')
    part_a(foo_a, hash_obj)

    # Part B 
    print('\n--- Task1 Part B ---\n')

    str0: str = 'Hello'
    str1: str = 'beautiful'
    str2: str = 'world!'


    # str3: bytes = 'test'.encode('utf-8')
    # str3_hammed: bytes= get_single_hamm(str3)

    # print(str3)
    # print(str3_hammed)


    hashed_str0_original, hashed_str0_hammed = part_b(str0, hash_obj)
    print(f'Original Digest: {hashed_str0_original}')
    print(f'Hammed Digest:   {hashed_str0_hammed}\n')

    hashed_str1_original, hashed_str1_hammed = part_b(str1, hash_obj)
    print(f'Original Digest: {hashed_str1_original}')
    print(f'Hammed Digest:   {hashed_str1_hammed}\n')

    hashed_str2_original, hashed_str2_hammed = part_b(str2, hash_obj)
    print(f'Original Digest: {hashed_str2_original}')
    print(f'Hammed Digest:   {hashed_str2_hammed}\n')

    print('\n--- Task1 Part C ---\n')

    # Part C (option 1 because I am lazy...)
    process_graphs(hash_obj)

