# Challenge 26 - CTR bitflipping
#
# https://cryptopals.com/sets/4/challenges/26

import random
import challenge_18


def flip_ctr_bits(ciphertext, idx, old_char, new_char):
    new_ciphertext = bytearray(ciphertext)
    new_ciphertext[idx] ^= ord(old_char) ^ ord(new_char)

    return bytes(new_ciphertext)


def new_comment(user_input):
    key = deterministic_random_key()
    comment = comment_for(user_input)

    return challenge_18.AES_CTR(key).encrypt(comment, b"\x00")


def is_admin_comment(ciphertext):
    key = deterministic_random_key()
    plaintext = challenge_18.AES_CTR(key).decrypt(ciphertext, b"\x00")

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
    random.seed(26)
    return [random.getrandbits(8) for _ in range(16)]


if __name__ == '__main__':
    ciphertext = new_comment(b"*admin*true")
    # First '*' would appear at index 32 (beginning of comment)
    ciphertext = flip_ctr_bits(ciphertext, 32, "*", ";")
    # Second '*' would appear 6 bytes into the comment (index 38)
    ciphertext = flip_ctr_bits(ciphertext, 38, "*", "=")

    if is_admin_comment(ciphertext):
        print("Posted comment as admin")
    else:
        print("Posted comment as non-admin")
