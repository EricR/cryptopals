# Challenge 27 - Recover the key from CBC with IV=Key
#
# https://cryptopals.com/sets/4/challenges/27

import random
import unittest
import challenge_07
import challenge_10


class Challenge27(unittest.TestCase):
    def test_recover_key(self):
        real_key = deterministic_random_key()
        ciphertext = new_comment(b"AAAA")
        recovered_key = recover_key(ciphertext, read_comment)

        self.assertEqual(recovered_key, real_key)


def new_comment(user_input):
    key = deterministic_random_key()
    comment = comment_for(user_input)

    return challenge_10.AES_CBC(key, key).encrypt(comment)


def read_comment(ciphertext):
    key = deterministic_random_key()
    comment = challenge_10.AES_CBC(key, key).decrypt(ciphertext)

    # Verify ASCII compliance. Any character >= 0x80 will throw an exception
    # containing the plaintext.
    try:
        return comment.decode('ascii')
    except UnicodeDecodeError:
        error_msg = comment.decode('iso-8859-1')
        raise Exception("Invalid Message: {}".format(error_msg)) from None


def comment_for(user_input):
    before = b"comment1=cooking%20MCs;userdata="
    after = b";comment2=%20like%20a%20pound%20of%20bacon"

    return before + user_input + after


def deterministic_random_key():
    random.seed(27)
    return bytes([random.getrandbits(8) for _ in range(16)])


def recover_key(ciphertext, oracle):
    """
    Uses a decryption oracle to recover the IV, which in this case happens to
    also be the key.

    Let:

    C'₁ = C₁
    C'₂ = 0x00
    C'₃ = C₁

    And consider that:

    P'₃ = D(C'₃) ⊕ C'₂
    P'₃ = D(C₁)  ⊕ C'₂
    P'₃ = D(C₁)  ⊕ 0x00
    P'₃ = D(C₁)

    P'₁ = D(C₁) ⊕ IV

    Which implies that:

    P'₁ = P'₃ ⊕ IV
    IV  = P'₁ ⊕ P'₃
    """
    blocks = challenge_07.as_blocks(ciphertext, 16)
    key = b""
    error_msg = b""

    # Leak the exception containing the plaintext to the attacker.
    try:
        oracle(blocks[0] + (b"\x00" * 16) + blocks[0] + b"".join(blocks[1:5]))
    except Exception as e:
        error_msg = str(e)

    # Offset for actual error string is 17, which is all we really care about
    error_msg = error_msg[17:].encode('iso-8859-1')
    plaintext = challenge_07.as_blocks(error_msg, 16)

    # Recover the IV (the key)
    for i, c in enumerate(plaintext[0]):
        key += bytes([c ^ plaintext[2][i]])

    return key


if __name__ == '__main__':
    unittest.main()
