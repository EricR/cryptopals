# Challenge 14 - Byte-at-a-time ECB decryption (Harder)
#
# https://cryptopals.com/sets/2/challenges/14

import random
import unittest
import challenge_7
import challenge_11
import challenge_12


class Challenge14(unittest.TestCase):
    def test_determine_offset(self):
        offset = determine_offset(encryption_oracle, 16)
        self.assertEqual(offset, len(deterministic_random_bytes()))

    def test_plaintext_recovery(self):
        plaintext = recover_plaintext(encryption_oracle)
        self.assertEqual(plaintext, challenge_12.secret)


def deterministic_random_bytes():
    random.seed(123)
    size = random.randint(100, 1000)

    return bytes([random.getrandbits(8) for _ in range(size)])


def encryption_oracle(plaintext):
    key = challenge_12.deterministic_random_key()
    prefix = deterministic_random_bytes()

    return challenge_11.AES_ECB(key).encrypt(prefix + plaintext
                                             + challenge_12.secret)


def determine_offset(oracle, block_size):
    """
    Determines the offset in which user input starts within the ciphertext by
    analyzing what injected padding causes a repeated block.
    """
    for i in range(1, 128):
        ciphertext = oracle(b"A" * i)
        blocks = challenge_7.as_blocks(ciphertext, block_size)
        last = None

        for idx, block in enumerate(blocks):
            if block == last:
                return idx * block_size - (i - block_size)
            last = block


def recover_plaintext(oracle):
    """
    Implements an attack similar to that in challenge 12, but accounts for the
    fact that some unknown characters are now inserted before any user input
    (referred to as an "offset" below).
    """
    plaintext = bytearray()
    block_size, text_size, _ = challenge_12.determine_block_stats(oracle)
    offset = determine_offset(oracle, block_size)
    extra_blocks = offset // block_size

    # Account for an extra block when the offset isn't perfectly aligned with
    # the block size
    if offset % block_size != 0:
        extra_blocks += 1

    extra_padding = extra_blocks * block_size - offset

    for i in range(1, text_size-offset+1):
        # Pad so that AES-128-ECB(random-prefix || padding || recovered
        # plaintext) leaves only one unknown byte in the current block at a
        # time
        padding_len = (block_size - i) % block_size + extra_padding
        padding = b"A" * padding_len

        # Keep track of which block we're working on
        block_n = len(plaintext) // block_size + extra_blocks
        block_start = block_n * block_size
        block_end = block_start + block_size
        block = oracle(padding)[block_start:block_end]

        # Guess the unknown byte (n)
        for n in [bytes([n]) for n in range(256)]:
            guess = oracle(padding + plaintext + n)[block_start:block_end]
            if guess == block:
                plaintext += n
                break

    return plaintext

if __name__ == '__main__':
    unittest.main()
