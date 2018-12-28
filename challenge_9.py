# Challenge 9 - Implement PKCS#7 padding
#
# https://cryptopals.com/sets/2/challenges/9

import unittest

class Challenge9(unittest.TestCase):
    def test_pkcs7(self):
        self.assertEqual(pkcs7(bytes("YELLOW SUBMARINE", 'ascii'), 20),
            b"YELLOW SUBMARINE\x04\x04\x04\x04")
        self.assertEqual(pkcs7(bytes("AAAAAAAAAAAAAAA", 'ascii'), 16),
            b"AAAAAAAAAAAAAAA\x01")

def pkcs7(data, size):
    nblocks = int(len(data) / size)
    last_block = data[nblocks*size:]
    padding = (size - len(last_block)) % size

    return bytes(data) + bytes(chr(padding) * padding, 'ascii')

if __name__ == '__main__':
    unittest.main()
