# Challenge 13 - ECB cut-and-paste
#
# https://cryptopals.com/sets/2/challenges/13

import unittest
import challenge_11
import challenge_12

class Challenge13(unittest.TestCase):
    def test_parse_key_value(self):
        test_str = "foo=bar&baz=qux"
        self.assertEqual(parse_key_value(test_str), {"foo": "bar", "baz": "qux"})

    def test_sanitize_email(self):
        self.assertEqual(sanitize_email("a@b.&=com"), "a@b.com")

def new_profile(email):
    key = challenge_12.deterministic_random_key()
    profile = bytes(profile_for(email), 'ascii')

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
    ciphertext = new_profile("test@test.com")
    print(get_profile(ciphertext))
