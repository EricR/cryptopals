# Challenge 9 - Implement PKCS#7 padding
#
# https://cryptopals.com/sets/2/challenges/9

import unittest

class Challenge9(unittest.TestCase):
    def test_pkcs7(self):
        self.assertEqual(pkcs7(b"YELLOW SUBMARINE", 20),
            b"YELLOW SUBMARINE\x04\x04\x04\x04")
        self.assertEqual(pkcs7(b"AAAAAAAAAAAAAAA", 16),
            b"AAAAAAAAAAAAAAA\x01")
        self.assertEqual(pkcs7(b"AAAAAAAAAAAAAAAA", 16),
            b"AAAAAAAAAAAAAAAA\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10")

    def test_remove_pkcs7(self):
        bytes1 = b"AAAAAAAAAAAAAAAA\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
        self.assertEqual(remove_pkcs7(bytes1, 16), b"AAAAAAAAAAAAAAAA")
        bytes2 = b"AAAAAA\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A"
        self.assertEqual(remove_pkcs7(bytes2, 16), b"AAAAAA")
        bytes3 = b"YELLOW SUBMARINE\x04\x04\x04\x04"
        self.assertEqual(remove_pkcs7(bytes3, 20), b"YELLOW SUBMARINE")

def pkcs7(data, block_size):
    data_size = len(data)
    nblocks = data_size // block_size
    last_offset = (nblocks-1) * block_size
    last_block = data[last_offset:]
    padding = (block_size - len(last_block)) % block_size

    # Handle case where the original data is an integer multiple of block_size
    if padding == 0:
        return bytes(data) + bytes(chr(block_size) * block_size, 'ascii')
    else:
        return bytes(data) + bytes(chr(padding) * padding, 'ascii')

def remove_pkcs7(data, block_size):
    data_size = len(data)
    nblocks = data_size // block_size
    last_offset = (nblocks-1) * block_size
    last_block = data[last_offset:]
    padding = last_block[-1]

    # Check if the padding is valid first
    if padding > block_size:
        raise ValueError("Invalid PKCS#7 padding for given block size")

    # Handle case where the original data is an integer multiple of block_size
    if last_block == bytes(chr(block_size) * block_size, 'ascii'):
        return data[:data_size-block_size]

    # Return the data minus the padding characters
    if last_block[-padding:] == bytes([padding]) * padding:
        return data[:data_size-padding]

    raise ValueError("Malformed PKCS#7 padding")

if __name__ == '__main__':
    unittest.main()
