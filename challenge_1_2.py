# Challenge 1.2 Fixed XOR
#
# https://cryptopals.com/sets/1/challenges/2

import unittest
import base64

class Challenge1_1(unittest.TestCase):
	def test_fixed_xor(self):
		result = fixed_xor("1c0111001f010100061a024b53535009181c",
			"686974207468652062756c6c277320657965")
		self.assertEqual(result, "746865206b696420646f6e277420706c6179")

def fixed_xor(str1, str2):
	assert(len(str1) == len(str2))

	bytes1 = bytearray.fromhex(str1)
	bytes2 = bytearray.fromhex(str2)
	size = len(bytes1)

	return bytes([bytes1[i] ^ bytes2[i] for i in range(size)]).hex()

if __name__ == '__main__':
	unittest.main()