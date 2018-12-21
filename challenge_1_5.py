# Challenge 1.5 Implement repeating-key XOR
#
# https://cryptopals.com/sets/1/challenges/5

import unittest

class Challenge1_5(unittest.TestCase):
	def test_repeating_xor(self):
		key = bytes("ICE", 'ascii')
		plaintext = bytes("Burning 'em, if you ain't quick and nimble\n" +
			"I go crazy when I hear a cymbal", "ascii")

		self.assertEqual(repeating_xor(key, plaintext).hex(),
			"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427" +
			"2765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b202831652863" +
			"26302e27282f")

def rotate(items):
	return items[1:] + items[:1]

def repeating_xor(key, plaintext):
	output = bytearray()

	for i in range(len(plaintext)):
		output.append(plaintext[i] ^ key[0])
		key = rotate(key)

	return bytes(output)

if __name__ == '__main__':
	unittest.main()
