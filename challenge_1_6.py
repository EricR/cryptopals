# Challenge 1.6 Break repeating-key XOR
#
# https://cryptopals.com/sets/1/challenges/6

import base64
import challenge_1_3
import challenge_1_5
import unittest

class Challenge1_6(unittest.TestCase):
	def test_hamming_distance(self):
		self.assertEqual(hamming_distance(bytes("this is a test", 'ascii'),
			bytes("wokka wokka!!!", 'ascii')), 37)

def bytes_to_bits(bytes1):
	return bin(int.from_bytes(bytes1, 'big'))

def to_blocks(list1, size):
	return [list1[i:i + size] for i in range(0, len(list1), size)]

def hamming_distance(bytes1, bytes2):
	"""
	Calculates the hamming distance in bits.
	"""
	bits1 = bytes_to_bits(bytes1)
	bits2 = bytes_to_bits(bytes2)
	length = min(len(bits1), len(bits2))

	# Calculate deletions
	distance = max(len(bits1), len(bits2)) - length

	# Calculate swaps
	for i in range(length):
		if bits1[i] != bits2[i]:
			distance += 1

	return distance

def avg_hamming_distance(bytes1, block_size):
	"""
	Calculates the average hamming distance in bits that occurs over blocks of a
	given size.
	"""
	distances = []
	prev_block = None

	for block in to_blocks(bytes1, block_size):
		if prev_block != None and len(block) == len(prev_block):
			distances.append(hamming_distance(block, prev_block) / len(block))
		prev_block = block

	return sum(distances) / len(distances)


def guess_keysize(bytes1, max_size):
	"""
	Calculates the most likely key size based on average hamming distance.
	"""
	avgs = [avg_hamming_distance(bytes1, size) for size in range(2, max_size + 1)]

	# Add 2 to index since that was our starting keysize
	return avgs.index(min(avgs)) + 2

def transpose_blocks(bytes1, size):
	"""
	Returns a transposed version of a given list of blocks.
	"""
	blocks = []

	for i in range(size):
		new_block = []
		for block in to_blocks(ciphertext, size):
			if i < len(block):
				new_block.append(block[i])
		blocks.append(new_block)

	return blocks

if __name__ == '__main__':
	ciphertext_hex = open("6.txt", "r").read()
	ciphertext = base64.b64decode(ciphertext_hex)
	keysize = guess_keysize(ciphertext, 40)
	key = bytearray()
	
	for block in transpose_blocks(ciphertext, keysize):
		key += challenge_1_3.guess_with_frequency(block)[0]

	plaintext = challenge_1_5.repeating_xor(key, ciphertext).decode()

	print("Key      : {}".format(key))
	print("Plaintext: {}".format(plaintext))
