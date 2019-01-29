# Challenge 20 - Break fixed-nonce CTR statistically
#
# https://cryptopals.com/sets/3/challenges/20

import challenge_3
import challenge_5
import challenge_18
import random
import base64


def deterministic_random_key():
    random.seed(20)
    return [random.getrandbits(8) for _ in range(16)]


def generate_ciphertexts():
    key = deterministic_random_key()
    content = bytes(open("20.txt", "r").read(), 'ascii')
    ciphertexts = []

    for line in content.split(b"\n"):
        decoded = base64.b64decode(line)
        ciphertext = challenge_18.AES_CTR(key).encrypt(decoded, b"0x00")
        ciphertexts.append(ciphertext)

    return ciphertexts


def transpose_ciphertexts(ciphertexts):
    return [bytes(c) for c in zip(*ciphertexts)]


def attack_repeating_ctr_nonce(ciphertexts):
    keystream = b""

    for ciphertext in transpose_ciphertexts(ciphertexts):
        keystream += challenge_3.guess_with_frequency(ciphertext)[0]

    return keystream


if __name__ == '__main__':
    ciphertexts = generate_ciphertexts()
    keystream = attack_repeating_ctr_nonce(ciphertexts)

    for ciphertext in ciphertexts:
        plaintext = challenge_5.repeating_xor(keystream, ciphertext)
        print(plaintext)
