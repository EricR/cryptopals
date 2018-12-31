# Challenge 11 - An ECB/CBC detection oracle
#
# https://cryptopals.com/sets/2/challenges/11

import secrets
import challenge_7
import challenge_8
import challenge_9
import challenge_10

class AES_ECB:
    def __init__(self, key):
        self.cipher = challenge_7.AES(key)

    def encrypt(self, plaintext):
        # Apply padding so all blocks end up as 16 bytes
        plaintext = challenge_9.pkcs7(plaintext, 16)

        # Break the plaintext up into blocks
        blocks = challenge_7.as_blocks(plaintext, 16)

        # All blocks are encrypted individually
        for i in range(len(blocks)):
            blocks[i] = self.cipher.encrypt(blocks[i])

        return b''.join(blocks)

    def decrypt(self, ciphertext):
        if len(ciphertext) % 16 != 0:
            raise ValueError("Invalid length of ciphertext")

        # Break the ciphertext up into blocks
        blocks = challenge_7.as_blocks(ciphertext, 16)

        # All blocks are decrypted individually
        for i in range(len(blocks)):
            blocks[i] = self.cipher.decrypt(blocks[i])

        return challenge_9.remove_pkcs7(b''.join(blocks), 16)

def random_key_or_iv():
    return secrets.token_bytes(16)

def random_padding():
    return bytes([0x00 for _ in range(secrets.randbelow(10) + 1)])

def encryption_oracle(plaintext):
    key = random_key_or_iv()
    plaintext = random_padding() + plaintext + random_padding()

    # Use ECB half the time and CBC the other half of the time
    if secrets.randbelow(2) == 1:
        return AES_ECB(key).encrypt(plaintext)
    else:
        iv = random_key_or_iv()
        return challenge_10.AES_CBC(key, iv).encrypt(plaintext)

def detect_mode(ciphertext):
    blocks = challenge_7.as_blocks(ciphertext, 16)

    if challenge_8.detect_aes_ecb(blocks)[1] > 1:
        return "ecb"
    else:
        return "cbc"
    
if __name__ == '__main__':
    ciphertext = encryption_oracle(bytes("A" * 64, 'ascii'))
    mode = detect_mode(ciphertext)
    
    print("Mode: {}".format(mode))
