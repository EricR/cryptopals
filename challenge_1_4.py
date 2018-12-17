# Challenge 1.4 Detect single-character XOR
#
# https://cryptopals.com/sets/1/challenges/4

import challenge_1_3

if __name__ == '__main__':
	max_score = 1.0
	best_key = bytes()
	best_plaintext = bytes()
	f = open("4.txt", "r")

	for line in f:
		ciphertext = bytes.fromhex(line)
		key, plaintext, score = challenge_1_3.guess_with_frequency(ciphertext)

		if score > max_score:
			max_score = score
			best_key = key
			best_plaintext = plaintext

	print("Key      : {}".format(best_key))
	print("Plaintext: {}".format(best_plaintext))
	print("Score    : {}".format(max_score))
