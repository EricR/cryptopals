# Challenge 3 - Single-byte XOR cipher
#
# https://cryptopals.com/sets/1/challenges/3

import challenge_2

letter_scores = {
    "e": 26, "t": 25, "a": 24, "o": 23, "i": 22, "n": 21, "s": 20, "h": 19,
    "r": 18, "d": 17, "l": 16, "c": 15, "u": 14, "m": 13, "w": 12, "f": 11,
    "g": 10, "y": 9,  "p": 8,  "b": 7,  "v": 6,  "k": 5,  "j": 4,  "x": 3,
    "q": 2,  "z": 1,  " ": 20
}


def frequency_score(plaintext):
    """
    Returns a score representing how closely letter frequencies match the
    expected values found in the English language.
    """
    return sum([letter_scores.get(chr(b), -5) for b in plaintext.lower()])


def guess_with_frequency(ciphertext):
    key = b""
    plaintext = b""
    max_score = 1.0

    for i in range(255):
        # Guess a repeating key and record the frequency score
        guessed_key = bytes.fromhex('{0:02x}'.format(i))
        guessed_plaintext = challenge_2.fixed_xor(guessed_key *
                                                  len(ciphertext), ciphertext)
        score = frequency_score(guessed_plaintext)

        if score > max_score:
            max_score = score
            key = guessed_key
            plaintext = guessed_plaintext

    return key, plaintext, max_score


if __name__ == '__main__':
    ciphertext = bytes.fromhex(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    key, plaintext, score = guess_with_frequency(ciphertext)

    print("Key      : {}".format(key.decode()))
    print("Plaintext: {}".format(plaintext.decode()))
    print("Score    : {}".format(score))
