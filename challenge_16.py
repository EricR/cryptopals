# Challenge 16 - CBC bitflipping attacks
#
# https://cryptopals.com/sets/2/challenges/16

import random
import challenge_10


def flip_cbc_bits(ciphertext, idx, old_char, new_char):
    """
    Flipping a bit in one block of ciphertext will corrupt the block, but will
    cause the corresponding bit of plaintext in the next block to flip. This is
    because during decryption in CBC mode, a block's plaintext is XOR'd with
    the previous block's ciphertext.


             Ciphertext               Ciphertext
                 |                         |
                 |---------*               |---------*
                 V         |               |         |
    Key ---> Decryption    |  Key ---> Decryption    |
                 |         |               |         |
    IV ------->(XOR)       *------------>(XOR)       *------ ...
                 |                         |
                 V                         V
             Plaintext                 Plaintext

    """
    new_ciphertext = bytearray(ciphertext)
    new_ciphertext[idx] ^= ord(old_char) ^ ord(new_char)

    return bytes(new_ciphertext)


def new_comment(user_input):
    key = deterministic_random_key()
    iv = deterministic_random_iv()
    comment = comment_for(user_input)

    return challenge_10.AES_CBC(key, iv).encrypt(comment)


def is_admin_comment(ciphertext):
    key = deterministic_random_key()
    iv = deterministic_random_iv()
    plaintext = challenge_10.AES_CBC(key, iv).decrypt(ciphertext)

    return b";admin=true;" in plaintext


def comment_for(user_input):
    before = b"comment1=cooking%20MCs;userdata="
    after = b";comment2=%20like%20a%20pound%20of%20bacon"

    return before + sanitize_user_input(user_input) + after


def sanitize_user_input(user_input):
    return user_input.decode().translate({ord(c): None for c in ';='}).encode()


def parse_key_value(str1):
    return dict(item.split("=") for item in str1.split(";"))


def deterministic_random_key():
    random.seed(234)
    return [random.getrandbits(8) for _ in range(16)]


def deterministic_random_iv():
    random.seed(345)
    return [random.getrandbits(8) for _ in range(16)]


if __name__ == '__main__':
    ciphertext = new_comment(b"AAAAAAAAAAAAAAAA*admin*true")
    # Offset = 49 - 16 (block size) = 33
    ciphertext = flip_cbc_bits(ciphertext, 32, "*", ";")
    # Offset = 55 - 16 (block size) = 39
    ciphertext = flip_cbc_bits(ciphertext, 38, "*", "=")

    if is_admin_comment(ciphertext):
        print("Posted comment as admin")
    else:
        print("Posted comment as non-admin")
