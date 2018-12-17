# Challenge 1.2 Single-Byte XOR Cipher
#
# https://cryptopals.com/sets/1/challenges/3

import challenge_1_2
from collections import Counter

lettersByFreq = {
	"e": 12.702,
	"t": 9.056,
	"a": 8.167,
	"o": 7.507,
	"i": 6.966,
	"n": 6.749,
	"s": 6.327,
	"h": 6.094,
	"r": 5.987,
	"d": 4.253,
	"l": 4.025,
	"c": 2.782,
	"u": 2.758,
	"m": 2.406,
	"w": 2.360,
	"f": 2.228,
	"g": 2.015,
	"y": 1.974,
	"p": 1.929,
	"b": 1.492,
	"v": 0.978,
	"k": 0.772,
	"j": 0.153,
	"x": 0.150,
	"q": 0.095,
	"z": 0.074,
}

def frequency_score(plaintext):
	"""
	Returns a score representing how closely letter frequencies match the expected
	values found in the English language.
	"""
	text = ""
	score = 1.0

	try:
		text = plaintext.decode('ascii').lower()
	except:
		return score

	for letter, _ in Counter(text).most_common():
		if letter in lettersByFreq:
			score *= lettersByFreq[letter]

	return score

if __name__ == '__main__':
	ciphertext = bytearray.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	recovered_key = bytes()
	recovered_plaintext = bytes()
	max_score = 1.0

	for i in range(255):
		possible_key = bytearray.fromhex('{0:02x}'.format(i))
		plaintext = challenge_1_2.fixed_xor(possible_key * len(ciphertext), ciphertext)
		score = frequency_score(plaintext)

		if score > max_score:
			max_score = score
			recovered_key = possible_key
			recovered_plaintext = plaintext

	print("Key      : {}".format(recovered_key.decode("utf-8")))
	print("Plaintext: {}".format(recovered_plaintext.decode("utf-8")))