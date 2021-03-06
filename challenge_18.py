# Challenge 18 - Implement CTR, the stream cipher mode
#
# https://cryptopals.com/sets/3/challenges/18

import challenge_07
import unittest
import base64


class AES_CTR:
    def __init__(self, key):
        self.cipher = challenge_07.AES(key)

    def encrypt(self, plaintext, nonce):
        blocks = challenge_07.as_blocks(plaintext, 16)
        keystream = b""
        ciphertext = b""

        # Produce the blocks we need for our keystream
        for i in range(len(blocks)):
            nonce_padded = nonce + b"\x00" * (8 - len(nonce))
            counter = bytes([i])
            counter_padded = counter + b"\x00" * (8 - len(counter))
            keystream += self.cipher.encrypt(nonce_padded + counter_padded)

        for i, c in enumerate(plaintext):
            ciphertext += bytes([c ^ keystream[i]])

        return ciphertext

    def decrypt(self, ciphertext, nonce):
        return self.encrypt(ciphertext, nonce)


class Challenge18(unittest.TestCase):
    def test_ctr_mode(self):
        cipher = AES_CTR(b"YELLOW SUBMARINE")
        ciphertext = base64.b64decode(b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY" +
                                      b"/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
        plaintext = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "

        self.assertEqual(cipher.decrypt(ciphertext, b"\x00").decode(),
                         plaintext)


if __name__ == '__main__':
    unittest.main()
