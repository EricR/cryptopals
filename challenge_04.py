# Challenge 4 - Detect single-character XOR
#
# https://cryptopals.com/sets/1/challenges/4

import challenge_03

if __name__ == '__main__':
    max_score = 1.0
    key = b""
    plaintext = b""

    for line in open("04.txt", "r"):
        guessed_key, guessed_plaintext, score = \
            challenge_03.guess_with_frequency(bytes.fromhex(line))

        if score > max_score:
            max_score = score
            key = guessed_key
            plaintext = guessed_plaintext

    print("Key      : {}".format(key))
    print("Plaintext: {}".format(plaintext.decode()))
    print("Score    : {}".format(max_score))
