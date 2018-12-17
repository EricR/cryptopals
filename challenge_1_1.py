# Challenge 1.1 Convert hex to base64
#
# https://cryptopals.com/sets/1/challenges/1

import unittest
import base64

class Challenge1_1(unittest.TestCase):
	def test_convert_hex_to_base64(self):
		result = hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
		
		self.assertEqual(result, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

def hex_to_base64(string):
	return base64.b64encode(bytearray.fromhex(string)).decode("ascii") 

if __name__ == '__main__':
	unittest.main()
