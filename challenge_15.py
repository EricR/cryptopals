# Challenge 15 - PKCS#7 padding validation
#
# https://cryptopals.com/sets/2/challenges/15

import challenge_9

# Already implemented PKCS#7 padding removal and validation in challenge 9,
# since it seemed required to complete challenge 12 without resorting to
# manually stripping PKCS#7 padding.

def pkcs7(data, block_size):
    challenge_9.pkcs7(data, block_size)

def remove_pkcs7(data, block_size):
    challenge_9.remove_pkcs7(data, block_size)
