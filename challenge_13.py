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

def forge_block(offset, plaintext, oracle):
    """
    Given an offset, plaintext, and oracle, forges a block with the proper
    padding.
    """
    b_size, _, _ = challenge_12.determine_block_stats(oracle)
    new_padding = bytes("A" * (b_size - offset), 'ascii')
    payload = new_padding + challenge_9.pkcs7(plaintext, b_size)
    ciphertext = oracle(payload)

    return challenge_7.as_blocks(ciphertext, b_size)[1]

def forge_padding_block(oracle):
    """
    Given an oracle, forges a block with all PKCS#7 padding (which occurs when
    the length of a plaintext is an integer multiple of the block size)
    """
    b_size, pt_size, padding = challenge_12.determine_block_stats(oracle)
    new_padding = bytes("A" *  padding, 'ascii')

    return challenge_7.as_blocks(oracle(new_padding), b_size)[-1]

def new_profile(email):
    """
    Acts as an oracle for profile_for. This is the only function we're allowed
    to rely on.
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
    # Forge a block with an offset of 6 to compensate for "email="
    forgery = forge_block(6, bytes("admin", 'ascii'), new_profile)

    # When email length is 13, the second block ends in "role="
    ciphertext = new_profile(bytes("test@test.com", 'ascii'))
    b_size, _, _ = challenge_12.determine_block_stats(new_profile)
    blocks = challenge_7.as_blocks(ciphertext, b_size)

    # "Cut and paste" blocks to provide the desired ciphertext
    print(get_profile(blocks[0] + blocks[1] + forgery))

    # Try another way of doing this. This version relies on generating a block
    # full of PKCS#7 padding and doing more block "cut and pasting"

    # When input length is 13, the second block ends in "role=". The last four
    # chars will become part of the email
    ciphertext = new_profile(bytes("AAAAAAAAA.com", 'ascii'))
    role_block = challenge_7.as_blocks(ciphertext, b_size)[1]

    # When input length is 15, the second block starts with last 5 chars
    ciphertext = new_profile(bytes("AAAAAAAAAAadmin", 'ascii'))
    admin_block = challenge_7.as_blocks(ciphertext, b_size)[1]

    # Grab a block that contains "=" so key value parsing still works
    ciphertext = new_profile(bytes("AAAAAAAAAA", 'ascii'))
    kv_end_block = challenge_7.as_blocks(ciphertext, b_size)[0]

    # Grab a block that contains an email key value minus the last four chars
    # (those come from role_block as described above)
    ciphertext = new_profile(bytes("test@test.", 'ascii'))
    email_block = challenge_7.as_blocks(ciphertext, b_size)[0]

    # Forge a block full of PKCS#7 padding so we don't end up with invalid
    # padding
    padding_block = forge_padding_block(new_profile)

    print(get_profile(email_block + role_block + admin_block + kv_end_block
        + padding_block))
