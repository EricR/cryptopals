# Challenge 8 - Detect AES in ECB mode
#
# https://cryptopals.com/sets/1/challenges/8

import base64
import challenge_7

def detect_aes_ecb(blocks):
    histogram = {}

    for block in blocks:
        histogram[block] = histogram.get(block, 0) + 1

    block = max(histogram, key=histogram.get)

    return block, histogram[block]

if __name__ == '__main__':
    max_score = 0
    block = b""

    for line in open("8.txt", "r"):
        ciphertext = base64.b64decode(line)
        blocks = challenge_7.as_blocks(ciphertext, 16)
        guessed_block, score = detect_aes_ecb(blocks)

        if score > max_score:
            max_score = score
            block = guessed_block

    print("Likely AES ECB Block: {}".format(block))
    print("Highest Score       : {}".format(max_score))
