# Challenge 19 - Break fixed-nonce CTR mode using substitutions
#
# https://cryptopals.com/sets/3/challenges/19

import challenge_18
import random
import base64


def deterministic_random_key():
    random.seed(19)
    return [random.getrandbits(8) for _ in range(16)]


def generate_ciphertexts():
    key = deterministic_random_key()
    content = bytes(open("19.txt", "r").read(), 'ascii')
    ciphertexts = []

    for line in content.split(b"\n"):
        decoded = base64.b64decode(line)
        ciphertext = challenge_18.AES_CTR(key).encrypt(decoded, b"0x00")
        ciphertexts.append(ciphertext)

    return ciphertexts


def repeated_chars(a, b):
    repeats = 0

    if len(a) > len(b):
        a, b = b, a

    for i, c in enumerate(a):
        if c == b[i]:
            repeats += 1

    return repeats


if __name__ == '__main__':
    ciphertexts = generate_ciphertexts()

    # Find most similar ciphertexts
    for i, ciphertext_a in enumerate(ciphertexts):
        other_ciphertexts = ciphertexts[:i] + ciphertexts[i+1:]
        most_repeats = 0
        most_alike_ciphertext = None

        for ciphertext_b in other_ciphertexts:
            repeats = repeated_chars(ciphertext_a, ciphertext_b)

            if repeats > most_repeats:
                most_repeats = repeats
                most_alike_ciphertext = ciphertext_b

        print(ciphertext_a)
        print(most_alike_ciphertext)
        print("")

    # Find most frequent characters in ciphertexts
    frequencies = dict()

    for ciphertext in ciphertexts:
        for b in ciphertext:
            frequencies[bytes([b])] = frequencies.get(bytes([b]), 0) + 1

    print(sorted(frequencies.items(), key=lambda x: x[1]))

    # OK, enough experimenting for now... This approach is definitely
    # suboptimal.
