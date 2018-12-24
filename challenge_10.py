# Challenge 10 - Implement CBC mode
#
# https://cryptopals.com/sets/2/challenges/10

import challenge_2
import challenge_7
import challenge_9
import base64
import unittest

class AES_CBC:
    def __init__(self, key, iv):
        if len(iv) != 16:
            raise ValueError("Invalid length of IV")

        self.cipher = challenge_7.AES(key)
        self.iv = iv

    def encrypt(self, plaintext):
        # Pad the plaintext so that it fits evenly into blocks
        plaintext = challenge_9.pkcs7(plaintext, 16)

        # Break the plaintext up into blocks
        blocks = challenge_7.as_blocks(plaintext, 16)

        # First block is the result of encrypt(blocks[0] ^ IV)
        blocks[0] = self.cipher.encrypt(challenge_2.fixed_xor(blocks[0], self.iv))

        # All other blocks are the result of encrypt(blocks[i] ^ blocks[i-1])
        for i in range(1, len(blocks)):
            blocks[i] = self.cipher.encrypt(challenge_2.fixed_xor(blocks[i], blocks[i-1]))

        return blocks

    def decrypt(self, ciphertext):
        if len(ciphertext) % 16 != 0:
            raise ValueError("Invalid length if ciphertext")

        # Break the ciphertext up into blocks
        blocks = challenge_7.as_blocks(ciphertext, 16)
        decrypted = blocks

        # All but the first decrypted block are the result of
        # decrypt(blocks[i]) ^ blocks[i-1]
        for i in range(len(decrypted)-1,0,-1):
            decrypted[i] = challenge_2.fixed_xor(self.cipher.decrypt(blocks[i]), blocks[i-1])

        # First decrypted block is the result of decrypt(blocks[0]) ^ IV
        decrypted[0] = challenge_2.fixed_xor(self.cipher.decrypt(blocks[0]), self.iv)

        return decrypted

if __name__ == '__main__':
    key = bytes("YELLOW SUBMARINE", 'ascii')
    iv = bytes.fromhex("00000000000000000000000000000000")
    cipher = AES_CBC(key, iv)
    ciphertext_hex = open("10.txt", "r").read()
    ciphertext = base64.b64decode(ciphertext_hex)

    print("Plaintext: {}".format(cipher.decrypt(ciphertext)))