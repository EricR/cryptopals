# Challenge 12 - Byte-at-a-time ECB decryption (Simple)
#
# https://cryptopals.com/sets/2/challenges/12

import random
import base64
import unittest
import challenge_7
import challenge_11

# secret = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd2" +
#     "4gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdX" +
#     "N0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
secret = bytes("test", 'ascii')

class Challenge12(unittest.TestCase):
    def test_determine_block_stats(self):
        b_size, pt_size, padding = determine_block_stats(encryption_oracle)
        self.assertEqual(b_size, 16)
        self.assertEqual(pt_size, len(secret))
        self.assertEqual(padding, 6)

    def test_determine_mode(self):
        mode = detect_mode(encryption_oracle)
        self.assertEqual(mode, 'ecb')

    def test_plaintext_recovery(self):
        plaintext = recover_plaintext(encryption_oracle)
        self.assertEqual(plaintext, secret)

def deterministic_random_key():
    random.seed(123)
    return [random.getrandbits(8) for _ in range(16)]

def encryption_oracle(plaintext):
    key = deterministic_random_key()
    return challenge_11.AES_ECB(key).encrypt(plaintext + secret)

def determine_block_stats(oracle):
    initial_size = len(oracle(bytes()))
    padding = 0

    for i in range(0,256):
        ciphertext = oracle(bytes('A' * i, 'ascii'))

        # Watch for a new block being appended
        if len(ciphertext) > initial_size:
            block_size = len(ciphertext) - initial_size
            n_blocks = initial_size // block_size
            plaintext_size = n_blocks * block_size - padding

            return block_size, plaintext_size, padding
        else:
            padding += 1

def recover_plaintext(oracle):
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
    block_size, text_size, _ = determine_block_stats(encryption_oracle)

    for i in range(1, text_size+1):
        # Pad so that AES-128-ECB(padding || recovered plaintext) leaves only
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
                break

    return bytes(plaintext)

def detect_mode(oracle):
    plaintext = bytes("A" * 128, 'ascii')
    return challenge_11.detect_mode(oracle(plaintext))

if __name__ == '__main__':
    unittest.main()
