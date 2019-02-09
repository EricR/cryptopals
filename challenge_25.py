# Challenge 25 - Break "random access read/write" AES CTR
#
# https://cryptopals.com/sets/3/challenges/25

import random
import base64
import challenge_11
import challenge_18


def deterministic_random_key():
    random.seed(25)
    return [random.getrandbits(8) for _ in range(16)]


def encrypt(plaintext):
    cipher = challenge_18.AES_CTR(deterministic_random_key())
    return cipher.encrypt(plaintext, b"\x00")


def get_plaintext():
    ciphertext = base64.b64decode(open("25.txt", "rb").read())
    cipher = challenge_11.AES_ECB(b"YELLOW SUBMARINE")

    return bytearray(cipher.decrypt(ciphertext))


def get_ciphertext():
    return encrypt(get_plaintext())


def edit(offset, newtext):
    """
    Performs an edit, which "seeks" into the ciphertext, decrypts it, and
    re-encrypts it with a provided plaintext at a provided offset.
    """
    plaintext = get_plaintext()
    plaintext[offset:offset + len(newtext)] = newtext

    return encrypt(plaintext)


def recover_plaintext(ciphertext, edit_func):
    """
    Recovers plaintext by using the edit function to first recover the original
    keystream. This happens when AES-CTR adds our edited plaintext (all zero
    bytes) to the keystream, since A XOR 0x00 = A.

    Once the keystream is recovered, XORs the ciphertext with the it to remove
    the keystream and leave only the plaintext.
    """
    new_plaintext = b"\x00" * len(ciphertext)
    new_cipheretext = edit_func(0, new_plaintext)
    plaintext = b""

    for i, c in enumerate(new_cipheretext):
        plaintext += bytes([c ^ ciphertext[i]])

    return plaintext


if __name__ == '__main__':
    ciphertext = get_ciphertext()
    plaintext = recover_plaintext(ciphertext, edit)

    print(plaintext.decode())
