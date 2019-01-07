# Challenge 17 - The CBC padding oracle
#
# https://cryptopals.com/sets/3/challenges/17

import random
import challenge_9
import challenge_10


def get_ciphertext():
    key = deterministic_random_key()
    iv = deterministic_random_iv()
    plaintext = bytes(select_random_string(), 'ascii')
    ciphertext = challenge_10.AES_CBC(key, iv).encrypt(plaintext)

    return ciphertext, iv


def oracle(ciphertext):
    key = deterministic_random_key()
    iv = deterministic_random_iv()

    try:
        challenge_10.AES_CBC(key, iv).decrypt(ciphertext)
    except challenge_9.PaddingError:
        return False

    return True


def select_random_string():
    content = open("17.txt", "r").read()
    lines = content.split("\n")

    return random.choice(lines)


def deterministic_random_key():
    random.seed(531)
    return [random.getrandbits(8) for _ in range(16)]


def deterministic_random_iv():
    random.seed(602)
    return [random.getrandbits(8) for _ in range(16)]

if __name__ == '__main__':
    print(get_ciphertext())
    print(oracle(b"test"))
