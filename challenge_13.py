# Challenge 13 - ECB cut-and-paste
#
# https://cryptopals.com/sets/2/challenges/13

import unittest
import challenge_7
import challenge_9
import challenge_11
import challenge_12

class Challenge13(unittest.TestCase):
    def test_parse_key_value(self):
        test_str = "foo=bar&baz=qux"
        self.assertEqual(parse_key_value(test_str), {"foo": "bar", "baz": "qux"})

    def test_sanitize_email(self):
        self.assertEqual(sanitize_email("a@b.&=com"), "a@b.com")

def forge_block(offset, plaintext, block_size, oracle):
    """
    Given an offset and a plaintext, forges a block with the proper padding.
    """
    new_padding = bytes("A" * (block_size - offset), 'ascii')
    payload = new_padding + challenge_9.pkcs7(plaintext, block_size)
    ciphertext = oracle(payload)

    return challenge_7.as_blocks(ciphertext, block_size)[1]

def new_profile(email):
    """
    Acts as an oracle for profile_for. This is the only function we're allowed
    to use.
    """
    key = challenge_12.deterministic_random_key()
    profile = bytes(profile_for(email.decode()), 'ascii')

    return challenge_11.AES_ECB(key).encrypt(profile)

def get_profile(ciphertext):
    key = challenge_12.deterministic_random_key()
    plaintext = challenge_11.AES_ECB(key).decrypt(ciphertext).decode()

    return parse_key_value(plaintext)

def profile_for(email):
    return "email={}&uid=10&role=user".format(sanitize_email(email))

def sanitize_email(email):
    return email.translate({ord(c): None for c in '&='})

def parse_key_value(str1):
    return dict(item.split("=") for item in str1.split("&"))

if __name__ == '__main__':
    block_size, _ = challenge_12.determine_block_and_plaintext_size(new_profile)

    # Forge a block with an offset of 6 to compensate for "email="
    forgery = forge_block(6, bytes("admin", 'ascii'), block_size, new_profile)

    # Email length must be a multiple of 13 so that the second block ends in
    # "role="
    ciphertext = new_profile(bytes("test@test.com", 'ascii'))
    blocks = challenge_7.as_blocks(ciphertext, block_size)

    # "Cut and paste" blocks to provide the desired ciphertext
    print(get_profile(blocks[0] + blocks[1] + forgery))
