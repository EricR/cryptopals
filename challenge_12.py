# Challenge 12 - Byte-at-a-time ECB decryption (Simple)
#
# https://cryptopals.com/sets/2/challenges/12

import random
import base64
import unittest
import challenge_7
import challenge_11

secret = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd2" +
    "4gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdX" +
    "N0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

class Challenge12(unittest.TestCase):
    def test_plaintext_recovery(self):
        b_size, pt_size = determine_block_and_plaintext_size(encryption_oracle)
        self.assertEqual(b_size, 16)
        self.assertEqual(pt_size, len(secret))
        mode = detect_mode(encryption_oracle, b_size)
        self.assertEqual(mode, 'ecb')
        print("Ciphertext:\n{}".format(encryption_oracle(secret)))
        print("")
        plaintext = recover_plaintext(encryption_oracle, pt_size, b_size)
        self.assertEqual(plaintext, secret)

def deterministic_random_key():
    random.seed(123)
    return [random.getrandbits(8) for _ in range(16)]

def encryption_oracle(plaintext):
    key = deterministic_random_key()
    return challenge_11.AES_ECB(key).encrypt(plaintext + secret)

def determine_block_and_plaintext_size(oracle):
    initial_size = len(oracle(bytes()))
    padding = 0

    for i in range(1,128):
        ciphertext = oracle(bytes('A' * i, 'ascii'))

        # Watch for a new block being appended
        if len(ciphertext) > initial_size:
            block_size = len(ciphertext) - initial_size
            n_blocks = initial_size // block_size
            plaintext_size = n_blocks * block_size - padding

            return block_size, plaintext_size
        else:
            padding += 1

def recover_plaintext(oracle, text_size, block_size):
    """
    Exploits the fact that ECB mode is used and that we can prepend data to the
    unknown plaintext before encryption. By intentionally padding the unknown
    plaintext with known bytes, we can create a block that contains only one
    unknown byte at a time. We can then guess it using the oracle (only 256
    possibilities), adjust the padding to add a new unknown byte, and repeat
    until we have an entire block decrypted. This process can be repeated for
    each block until the entire ciphertext is decrypted.
    """  
    plaintext = bytearray()

    for i in range(1, text_size+1):
        # Pad so that encrypt(padding || recovered plaintext) leaves only
        # one unknown byte in the current block at a time
        padding_len = (block_size - i) % block_size
        padding = bytes('A' * padding_len, 'ascii')

        # Keep track of which block we're working on
        block_start = (len(plaintext) // block_size) * block_size
        block_end = block_start + block_size
        block = oracle(padding)[block_start:block_end]

        # Guess the unknown byte (n)
        for n in [bytes([n]) for n in range(256)]:
            guess = oracle(padding + plaintext + n)[block_start:block_end]

            if guess == block:
                plaintext += n
                print("Recovered {}/{}: {}".format(i, text_size, bytes(plaintext)), end="\r")
                break

    print("")
    return bytes(plaintext)

def detect_mode(oracle, block_size):
    plaintext = bytes("A" * 64, 'ascii')
    return challenge_11.detect_mode(oracle(plaintext))

if __name__ == '__main__':
    unittest.main()
