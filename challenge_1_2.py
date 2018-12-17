# Challenge 1.2 Fixed XOR
#
# https://cryptopals.com/sets/1/challenges/2

import unittest
import base64

class Challenge1_2(unittest.TestCase):
	def test_fixed_xor(self):
		bytes1 = bytearray.fromhex("1c0111001f010100061a024b53535009181c")
		bytes2 = bytearray.fromhex("746865206b696420646f6e277420706c6179")
		result = fixed_xor(bytes1, bytes2).hex()

		self.assertEqual(result, "686974207468652062756c6c277320657965")

def fixed_xor(bytes1, bytes2):
	assert(len(bytes1) == len(bytes2))

	return bytes([bytes1[i] ^ bytes2[i] for i in range(len(bytes1))])

if __name__ == '__main__':
	unittest.main()
