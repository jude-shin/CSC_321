from dataclasses import dataclass
from Crypto.Util import number
from Crypto.Hash import SHA256

import secrets


from math import gcd, lcm

from cbc.cbc import encrypt_cbc, decrypt_cbc

BLOCK_SIZE = 16

#Wasnt too sure what was meant by "text book RSA" so I followed this wikipedia key generation steps (1-5)
# https://en.wikipedia.org/wiki/RSA_cryptosystem?#Key_generation

def gen_primes_for_rsa(numBits, e):
    k = numBits >> 1
    p = number.getStrongPrime(k, e=e)
    q = number.getStrongPrime(k, e=e)
    while p == q:
        q = number.getStrongPrime(k, e=e)
    assert gcd(e, p-1) == 1 and gcd(e, q-1) == 1
    return p, q

# helper to pad text bytes with pkcs#7 padding
def add_padding(text: bytes, block_size: int) -> bytes:
    # Get the remainder that is needed to become a multiple of block_size
    k: int = block_size - len(text)%block_size

    # k(byte) will be repeated k times
    single_byte: bytes = k.to_bytes(1, 'big')
    padding: bytes = single_byte * k

    # Append the padding to the end of the text 
    return text + padding 

@dataclass
class ParticipantRSA:
    #declared at startup
    numBits: int = 2048
    e: int = 65537
    p: int = None
    q: int = None
    n: int = None
    totient_of_n: int = None

    # recv from peer, this info is public
    peer_n: int = None
    peer_e: int = None

    # computed with peer info
    d: int = None

    #key that gets computed by sending RSA header
    secretKey: bytes = None

    # generate RSA stuff
    def generate_keys(self): 
        self.p, self.q = gen_primes_for_rsa(self.numBits, self.e)
        self.n = self.p * self.q
        self.totient_of_n = lcm(self.p - 1, self.q - 1)
        self.d = pow(self.e, -1, self.totient_of_n)  # private exponent
    
    #exchange public values (e and n)
    def set_peer_public(self, n: int, e: int = 65537):
        self.peer_n = n
        self.peer_e = e

    # --- RSA key transport (one-time or whenever you want to rotate) ---
    def send_key(self, other: "ParticipantRSA"):
        sym = secrets.token_bytes(16)
        self.secretKey = SHA256.new(sym).digest()[:16]   # hash before storing
        m = int.from_bytes(sym, 'big')
        c = pow(m, self.peer_e, self.peer_n)            #
        rsa_ct = c.to_bytes((self.peer_n.bit_length()+7)//8, 'big')
        other.recv_key(rsa_ct)

    def recv_key(self, rsa_ct: bytes):
        c = int.from_bytes(rsa_ct, 'big')
        m = pow(c, self.d, self.n)
        k_bytes = m.to_bytes((m.bit_length()+7)//8 or 1, 'big')  # minimal big-endian
        # if len(k_bytes) < BLOCK_SIZE:
        #     k = k.rjust(BLOCK_SIZE, b'\x00')
        self.secretKey = SHA256.new(k_bytes).digest()[:BLOCK_SIZE] 

    # --- AES-CBC messaging (exact style from your Task 2) ---
    def send_message(self, message: bytes, other: "ParticipantRSA"):
        randomIV = secrets.token_bytes(BLOCK_SIZE)
        padded_message = add_padding(message, BLOCK_SIZE)   # your helper
        encrypted_message = randomIV + encrypt_cbc(padded_message, self.secretKey, randomIV)
        other.recv_message(encrypted_message)

    def recv_message(self, encrypted_message: bytes):
        randomIV = encrypted_message[:BLOCK_SIZE]
        ciphertext = encrypted_message[BLOCK_SIZE:]
        decrypted_message = decrypt_cbc(ciphertext, self.secretKey, randomIV)
        print(f"Decrypted message: {decrypted_message.decode('utf-8')}")

    # Trudy helpers: prepare c' so Alice will derive k_bytes (and set Trudy.secretKey)
    def prepare_cprime_for_known_k(self, recipient_n: int, recipient_e: int, k_bytes: bytes):
        # x := k_bytes  (attacker-chosen preimage)
        x_int = int.from_bytes(k_bytes, 'big')
        cprime_int = pow(x_int, recipient_e, recipient_n)           # c' = x^e mod n
        self.cprime = cprime_int.to_bytes((recipient_n.bit_length()+7)//8, 'big')
        self.secretKey = SHA256.new(k_bytes).digest()[:BLOCK_SIZE]  # k = H(x)

    def prepare_cprime_one(self, recipient_n: int):
        # x := 0x01
        self.cprime = (1).to_bytes((recipient_n.bit_length()+7)//8, 'big')
        self.secretKey = SHA256.new(b'\x01').digest()[:BLOCK_SIZE]  # k = H(0x01)

    def make_malleable_signature(self, sig1_int: int, sig2_int: int, pub_n: int):
        return (sig1_int * sig2_int) % pub_n
    

def part1_basic_rsa_test():
    # Alice and Bob setup
    Alice = ParticipantRSA(numBits=2048, e=65537)
    Bob   = ParticipantRSA(numBits=2048, e=65537)

    # keygen
    Alice.generate_keys()
    Bob.generate_keys()

    # exchange public info (n,e)
    Alice.set_peer_public(Bob.n, Bob.e)
    Bob.set_peer_public(Alice.n, Alice.e)

    # Exchange symmetric keys via RSA
    Alice.send_key(Bob)   
    Bob.send_key(Alice)   

    # test that these keys are legit, and we can send messages
    Alice.send_message(b"Hello Bob (sent using RSA generated key)", Bob)
    Bob.send_message(b"Hello Alice (sent using RSA generated key)", Alice)

def part2_trudy_replaces_with_one():
    Alice = ParticipantRSA()
    Bob   = ParticipantRSA()
    Trudy = ParticipantRSA()

    Alice.generate_keys()
    Bob.generate_keys()
    Trudy.generate_keys()

    Bob.set_peer_public(Alice.n, Alice.e)
    Trudy.prepare_cprime_one(Alice.n)
    Alice.recv_key(Trudy.cprime)
    Alice.send_message(b"Hello Trudy (intercepted by trudy by injecting c')", Trudy)

#This is another example of how RSA's maleability could be exploited (not explicitly asked for). This is much worse than the "replace with 1" attack
#Not only can Trudy see the messages being sent, she can now also send her own messages to Alice and Bob, pretending to be legitimate
def part2_trudy_forces_k():
    Alice = ParticipantRSA()
    Bob   = ParticipantRSA()
    Trudy = ParticipantRSA()

    Alice.generate_keys()
    Bob.generate_keys()
    Trudy.generate_keys()

    Bob.set_peer_public(Alice.n, Alice.e)   # Bob wants to talk to Alice, but never does

    #Trudy creates a completely arbitrary k, and injects a c' that will cause Alice to derive that k
    #Trudy can then decrypt any messages Alice sends to Bob, since she knows k
    chosen_k = secrets.token_bytes(BLOCK_SIZE)
    Trudy.prepare_cprime_for_known_k(Alice.n, Alice.e, chosen_k)
    Alice.recv_key(Trudy.cprime)
    Alice.send_message(b"Hello Bob (intercepted by Trudy by forcing k and injecting c')", Trudy)
    Trudy.send_message(b"Hello Alice, Im Bob, (total lies, this is really Trudy)", Alice)


def part2_malleability_demo():
    Alice = ParticipantRSA()
    Alice.generate_keys()
    m1 = 12345678901234567890 % Alice.n
    m2 = 9876543210987654321 % Alice.n
    sig1 = pow(m1, Alice.d, Alice.n)
    sig2 = pow(m2, Alice.d, Alice.n)
    sig3 = (sig1 * sig2) % Alice.n
    m3 = (m1 * m2) % Alice.n
    print ("observed signature 1: " + str(sig1) + "\nobserved signature 2: " + str(sig2) + "\ngenerated signature, also valid: " + str(sig3) + "\nthis signature is valid for message: " + str(m3))
    print("sig3 OK:", pow(sig3, Alice.e, Alice.n) == m3)

if __name__ == "__main__":
    #shows 1) from task 3
    print("basic RSA test")
    part1_basic_rsa_test()
    print("\ntrudy replaces c' 1 demo")
    part2_trudy_replaces_with_one()
    print("\ntrudy can just create a key, and inject c'. demo (example of another maleability attack, not specified in assignment)")
    part2_trudy_forces_k()
    print("\nmaleability demo")
    part2_malleability_demo()
