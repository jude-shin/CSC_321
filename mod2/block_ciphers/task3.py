import matplotlib.pyplot as plt
from matplotlib.ticker import LogLocator, LogFormatter, FuncFormatter

import numpy as np
import subprocess
from pathlib import Path
import math

from typing import List, Tuple, Union, Optional
from dataclasses import dataclass
import re

@dataclass
class RSAPerformance:
    bit_size: List[int]
    sign: List[float]
    verify: List[float]
    encrypt: List[float]
    decrypt: List[float] 

@dataclass
class AESPerformance:
    #3 parallel arrays
    key_size: List[int] #in bits
    performance: List[List[float]] # bytes/second
    block_size: List[int]

def get_openSSL_output(protocol_name: str) -> str:
    try:
        result = subprocess.run(['openssl', 'speed', '-elapsed',
                                 '-seconds', '10', protocol_name], #10=default
                                capture_output=True, text=True, check=True)
        output = result.stdout
        
        print(f"--- OpenSSL {protocol_name} Speed Test Output ---")
        print(output)
        return output
    except FileNotFoundError:
        print("Error: The 'openssl' command was not found.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Error: Command failed with exit code {e.returncode}")
        print(e.stderr)
        sys.exit(1)
    except Exception:
        print("something bricked on SSL cmd. idk")
        sys.exit(1)

#Operations per second -> bytes per second.
def compute_RSA_perf(ops_per_second: float, bit_size: int) -> float:
    key_size_in_bytes = bit_size / 8
    return ops_per_second * key_size_in_bytes

def parse_RSA_output(output_text: str) -> RSAPerformance:
    # Initialize lists inside the function
    data = RSAPerformance(
        bit_size=[],
        sign=[],
        verify=[],
        encrypt=[],
        decrypt=[]
    )

    # Split the entire output into individual lines
    lines = output_text.strip().split('\n')

    for line in lines:
        # Check if the line starts with the data identifier 'rsa '
        if line.startswith('rsa '):
            parts = line.split()

            
            # Check that line is the length we expect it to be.
            if len(parts) < 11:
                print(f"Skipping line due to missing data columns: '{line}'")
                continue
                 
            try:
                # Extract raw values
                bit_size = int(parts[1])
                # Expect: [7]: sign/s, [8]: verify/s, [9]: encr/s, [10]: decr/s
                sign_ops = float(parts[7])
                verify_ops = float(parts[8])
                encr_ops = float(parts[9])
                decr_ops = float(parts[10])

                data.bit_size.append(bit_size)
                # Compute throughput for all four metrics (Bytes/s)
                data.sign.append(compute_RSA_perf(sign_ops, bit_size))
                data.verify.append(compute_RSA_perf(verify_ops, bit_size))
                data.encrypt.append(compute_RSA_perf(encr_ops, bit_size))
                data.decrypt.append(compute_RSA_perf(decr_ops, bit_size))

            except (IndexError, ValueError) as e:
                print(f"Skipping malformed line: '{line}' due to error: {e}")
                continue

    return data


def display_RSA_graphs(data: RSAPerformance, pltPath: str): 
    plt.plot(data.bit_size, data.sign, label='sign')
    plt.plot(data.bit_size, data.verify, label='verify')
    plt.plot(data.bit_size, data.encrypt, label='encr.')
    plt.plot(data.bit_size, data.decrypt, label='decr.')

    plt.title('RSA Throughput vs. Key Size')
    plt.xlabel('Key Size (bits)')
    plt.ylabel('Throughput (bytes/sec)')
    plt.legend()
       
    # save linear + log variants
    p = Path('./newReport/plts/rsa.png')
    p.parent.mkdir(parents=True, exist_ok=True)

    linear = p.with_name(f"{p.stem}_linear{p.suffix}")
    plt.savefig(linear, bbox_inches='tight')

    plt.yscale('log')
    logp = p.with_name(f"{p.stem}_logarithmic{p.suffix}")
    plt.savefig(logp, bbox_inches='tight')

    plt.clf()


def parse_AES_output(output_text: str) -> AESPerformance:
    data = AESPerformance(
        key_size=[],
        performance=[],
        block_size=[]
    )

    lines = [ln.strip() for ln in output_text.strip().split("\n") if ln.strip()]

    for ln in lines:
        parts = ln.split()
        if not parts:
            continue
        #parse block sizes
        if parts[0] == "type":  #expect "... 16 bytes 64 bytes ... "
            for i in range(len(parts) - 1):
                if parts[i].isdigit() and parts[i + 1] == "bytes":
                    data.block_size.append(int(parts[i]))
        #parse throughput per key size
        elif parts[0].startswith("aes"):
            # extract key size (digits only)
            key_size = int("".join(ch for ch in parts[0] if ch.isdigit()))
            data.key_size.append(key_size)

            # convert throughput values (strip 'k', convert to bytes/sec)
            perf_row = []
            for val in parts[1:]:
                val_num = float(val.rstrip("kK")) * 1000.0
                perf_row.append(val_num)

            data.performance.append(perf_row)

    return data

def display_AES_graphs(data: AESPerformance, pltPath: str):
    p = Path(pltPath)
    p.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots()
    for i, ks in enumerate(data.key_size):
        ax.plot(data.block_size, data.performance[i], label=f"aes-{ks}-cbc")
    ax.set_title('AES Throughput')
    ax.set_xlabel('Block Size (bytes)')
    ax.set_ylabel('Throughput (bytes/sec)')
    ax.legend()

    # linear
    fig.savefig(p.with_name(f"{p.stem}_linear{p.suffix}"), bbox_inches='tight')

    plt.close(fig)



if __name__ == '__main__':
    
    img_folder = './newReport/plts/'

   # RSA
    if (rsa_output := get_openSSL_output("rsa")) is None:
        sys.exit(1)

    rsa_performance = parse_RSA_output(rsa_output)
    pltPath = img_folder + 'rsa.png'
    display_RSA_graphs(rsa_performance, pltPath)

    # AES
    if (aes_output := get_openSSL_output("aes")) is None:
        sys.exit(1)

    aes_performance = parse_AES_output(aes_output)
    pltPath = img_folder + 'aes.png'
    display_AES_graphs(aes_performance, pltPath) 

