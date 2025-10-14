
import sys

from cbc.cbc import encrypt_cbc, decrypt_cbc
from dataclasses import dataclass

from Crypto.Hash import SHA256
import secrets

BLOCK_SIZE: int = 16

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
class Participant:
    q: int                              #large prime number
    alpha: int                          #primitive root mod q
    intruder : bool = False             #when recving a message, an intruder may attempt multiple secret Keys (they set secret key to an array)
    myPrivateValue: int = None          #X_A or X_B
    myPublicValue: int = None           #Y_A or Y_B
    otherPublicValue: int = None        #Y_B or Y_A
    secretValue: int = None             #s
    secretKey: bytes =None              #k. Computed with SHA

    def generate_private(self):
        self.myPrivateValue = secrets.randbelow(self.q - 1) + 1  # 1 <= X < q

    def compute_public(self):
        self.myPublicValue = pow(self.alpha, self.myPrivateValue, self.q)    # Y = alpha^X mod q

    def givePublicValue(self, y: int):
        self.otherPublicValue = y

    def compute_secret_key(self):
        self.secretValue = pow(self.otherPublicValue, self.myPrivateValue, self.q)       # s = Y_other^X mod q

        hash_key = self.secretValue  # the shared secret int
        hash_bytes = hash_key.to_bytes((hash_key.bit_length()+7)//8 or 1, 'big')
        hash_obj = SHA256.new(hash_bytes)
        self.secretKey = hash_obj.digest()[:BLOCK_SIZE]  #use SHA digest as key, truncate to 16 bytes for AES-128
    
    def recv_message(self, encrypted_message: bytes):
        randomIV = encrypted_message[:BLOCK_SIZE]
        ciphertext = encrypted_message[BLOCK_SIZE:]
        if(self.intruder):
            if(type(self.secretKey) is (list or tuple)):
                for key in self.secretKey:
                    try :
                        decrypted_message = decrypt_cbc(ciphertext, key, randomIV)
                        try:
                            print(f"Possible Decrypted message with key {key.hex()}: {decrypted_message.decode('utf-8')}")
                        except:
                            print(f"Possible Decrypted message with key {key.hex()}: {decrypted_message} (not valid utf-8)")
                    except Exception as e: pass
                return
            
        decrypted_message = decrypt_cbc(ciphertext, self.secretKey, randomIV)

        print(f"Decrypted message: {decrypted_message.decode('utf-8')}")

    #send message using our secert key, and a random iv at start of msg in plaintext
    def send_message(self, message: bytes, otherParticipant: "Participant"):
        # Encrypt the message using AES with the shared secret key
        randomIV = secrets.token_bytes(BLOCK_SIZE)
        padded_message: bytes = add_padding(message, BLOCK_SIZE)
        encrypted_message = randomIV + encrypt_cbc(padded_message, self.secretKey, randomIV)

        otherParticipant.recv_message(encrypted_message)

    def set_secret_key(self, key: bytes):
        self.secretKey = key

def task2Case_1(q: int, alpha: int):
    print("Task 2, Case 1: Trudy intercepts and replaces public keys with q")

    Alice = Participant(q, alpha)
    Bob = Participant(q, alpha)
    Trudy = Participant(q, alpha)   # will immitate Alice to Bob

    Alice.generate_private()
    Alice.compute_public()

    Bob.generate_private()
    Bob.compute_public()

    #Trudy intercepts and replaces public keys with q
    Bob.givePublicValue(Trudy.q)
    Alice.givePublicValue(Trudy.q)  

    # Trudy knows the key will be computed using 0 as the secret value
    k_trudy = SHA256.new(b'\x00').digest()[:BLOCK_SIZE] 
    Trudy.set_secret_key(k_trudy)

    #they no longer exchange Y_A and Y_B
    # Bob.givePublicValue(Alice.myPublicValue)
    # Alice.givePublicValue(Bob.myPublicValue)

    Alice.compute_secret_key()
    Bob.compute_secret_key()

    Alice.send_message(b"Hello Bob!", Bob)
    Bob.send_message(b"Hello Alice!", Alice)

    print("\nTrudy can decrypt these messages too:")
    #Trudy, listening in on these messages, can now decrypt them as well
    Alice.send_message(b"Hello Bob #2!", Trudy)
    Bob.send_message(b"Hello Alice #2!", Trudy)

def task2Case_2(q: int, intercepted_alpha: int):
    if(intercepted_alpha not in [1, q-1, q]):
        print("Error: intercepted_alpha must be 1, q-1, or q")
        return
    
    #based on what alpha we want to use, Trudy can determine possible secret values
    possible_secretValues = [1] # if intercepted_alpha == 1
    alphaString = "1"
    if(intercepted_alpha == q):
        possible_secretValues = [0]
        alphaString = "q"
    elif(intercepted_alpha == q-1):
        possible_secretValues = [1, q-1]
        alphaString = "q-1"

    #compute possible secret keys based on possible secret values
    possible_secretKeys = []
    for sv in possible_secretValues:
        hash_key = sv  # the shared secret int
        hash_bytes = hash_key.to_bytes((hash_key.bit_length()+7)//8 or 1, 'big')
        hash_obj = SHA256.new(hash_bytes)
        possible_secretKeys.append(hash_obj.digest()[:BLOCK_SIZE])  #use SHA digest as key, truncate to 16 bytes for AES-128
    #

    #simulation where intercepted alpha is used, and Trudy tries all possible secret keys based on intercepted_alpha
    print("Task 2, Case 2: Trudy modifies alpha = " + alphaString)
    Alice = Participant(q, intercepted_alpha)
    Bob = Participant(q, intercepted_alpha)
    Trudy = Participant(q, intercepted_alpha, intruder = True)   # will immitate Alice to Bob

    Alice.generate_private()
    Alice.compute_public()

    Bob.generate_private()
    Bob.compute_public()

    # Trudy knows what the keys will look like
    Trudy.set_secret_key(possible_secretKeys)

    #Bob and Alice exchance public keys
    Bob.givePublicValue(Alice.myPublicValue)
    Alice.givePublicValue(Bob.myPublicValue)

    Alice.compute_secret_key()
    Bob.compute_secret_key()

    Alice.send_message(b"Hello Bob!", Bob)
    Bob.send_message(b"Hello Alice!", Alice)

    print("\nTrudy can decrypt these messages too:")
    #Trudy, listening in on these messages, can now decrypt them as well
    Alice.send_message(b"Hello Bob #2!", Trudy)
    Bob.send_message(b"Hello Alice #2!", Trudy)


if __name__ == '__main__':
    
    q = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371

    alpha = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5

    #Trudy replaces public keys with q
    task2Case_1(q, alpha)

    #Trudy modifies alpha to be 1, q-1, or q
    print("\n")
    alpha = 1
    task2Case_2(q, alpha)
    print("\n")
    alpha = q - 1
    task2Case_2(q, alpha)
    print("\n")
    alpha = q   
    task2Case_2(q, alpha)

