# Challenge 24 - Create the MT19937 stream cipher and break it
#
# https://cryptopals.com/sets/3/challenges/24

import unittest
import random
import time
import challenge_21


class MT19937StreamCipher():
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        """
        Encrypts using a keystream derived from MT19937 seeded with a secret.
        """
        prng = challenge_21.MT19937(self.key)
        keystream = b""
        ciphertext = b""
        keystream_len = div_round_up(len(plaintext), 4)  # 4 bytes in a 32-bit
                                                         # word

        # First generate a keystream of the correct length
        for _ in range(keystream_len):
            num = prng.extract_number()
            keystream += num.to_bytes(4, byteorder='big')

        # Then XOR the plaintext with the generated keystream
        for i, c in enumerate(plaintext):
            ciphertext += bytes([c ^ keystream[i]])

        return ciphertext

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)


class Challenge24(unittest.TestCase):
    def test_crack_16_bit_key_with_known_plaintext(self):
        known_plaintext = b"A" * 14
        key, ciphertext = generate_ciphertext(known_plaintext)

        success, recovered_key = crack_16_bit_key_with_known_plaintext(
            known_plaintext, ciphertext)

        self.assertEqual(success, True)
        self.assertEqual(recovered_key, key)

    def test_crack_timestamp_reset_token(self):
        seed = int(time.time())
        token = generate_password_reset_token(seed)

        # Simulate it taking some time to deliver the "password reset" email
        time.sleep(random.randint(10, 16))

        success, recovered_seed = crack_timestamp_reset_token(token)

        self.assertEqual(success, True)
        self.assertEqual(recovered_seed, seed)


def div_round_up(x, y):
    """
    Rounds up after integer division. This is done without importing Python's
    math.
    """
    return x // y + (x % y > 0)


def generate_ciphertext(known_plaintext):
    """
    Generates a random key and performs encrypt(random_prefix ||
    known_plaintext).
    """
    key = random.randint(0, 0xffff)
    prefix_len = random.randint(4, 12)
    random_prefix = [random.randint(0, 255) for _ in range(prefix_len)]
    cipher = MT19937StreamCipher(key)
    plaintext = bytes(random_prefix) + known_plaintext

    return key, cipher.encrypt(plaintext)


def generate_password_reset_token(seed):
    """
    Generates a random password reset token based on a provided seed.
    """
    cipher = challenge_21.MT19937(seed)
    length = 30

    # Generate a list of possible password characters
    pw = [chr(i) for i in range(65, 91)]  # A-Z
    pw += [chr(i) for i in range(97, 122)]  # a-z
    pw += [str(i) for i in range(0, 9)]  # 0-9

    # Construct a token by extracting random indexes for pw
    token = [pw[cipher.extract_number() % len(pw)] for _ in range(length)]

    return ''.join(token)


def crack_16_bit_key_with_known_plaintext(known_plaintext, ciphertext):
    """
    Guesses a 16-bit key and uses a known plaintext to check if it is correct.
    """
    for i in range(0xffff):
        cipher = MT19937StreamCipher(i)

        # Based on the length of the ciphertext, we know how many times the
        # PRNG was asked for a random number. We need to pad our known
        # plaintext with this many bytes so that the positions in the
        # keystream match.
        padding_len = len(ciphertext) - len(known_plaintext)
        padding = b"0" * padding_len

        # Generate the ciphertext for our guess
        guess = cipher.encrypt(padding + known_plaintext)

        # Disregard padding and check if our guess ciphertext matches the
        # original ciphertext
        if guess[padding_len:] == ciphertext[padding_len:]:
            return True, i

    return False, 0


def crack_timestamp_reset_token(ciphertext):
    """
    Guesses a seed that is based on a recent timestamp and is used to generate
    an observed ciphertext (a password reset token).
    """
    now = int(time.time())

    for seed in range((now - 17), now):
        result = generate_password_reset_token(seed)

        if result == ciphertext:
            return True, seed

    return False, 0


if __name__ == '__main__':
    unittest.main()
