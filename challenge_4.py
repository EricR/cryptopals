# Challenge 4 - Detect single-character XOR
#
# https://cryptopals.com/sets/1/challenges/4

import challenge_3

if __name__ == '__main__':
    max_score = 1.0
    key = bytes()
    plaintext = bytes()

    for line in open("4.txt", "r"):
        guessed_key, guessed_plaintext, score = challenge_3.guess_with_frequency(
            bytes.fromhex(line))

        if score > max_score:
            max_score = score
            key = guessed_key
            plaintext = guessed_plaintext

    print("Key      : {}".format(key))
    print("Plaintext: {}".format(plaintext))
    print("Score    : {}".format(max_score))
