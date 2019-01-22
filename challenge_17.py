# Challenge 17 - The CBC padding oracle
#
# https://cryptopals.com/sets/3/challenges/17

import random
import challenge_7
import challenge_9
import challenge_10


def get_ciphertext_and_iv():
    key = deterministic_random_key()
    iv = deterministic_random_iv()
    plaintext = bytes(select_random_string(), 'ascii')
    ciphertext = challenge_10.AES_CBC(key, iv).encrypt(plaintext)

    return ciphertext, iv


def padding_oracle(ciphertext):
    key = deterministic_random_key()
    iv = deterministic_random_iv()

    try:
        challenge_10.AES_CBC(key, iv).decrypt(ciphertext)
    except challenge_9.PaddingError:
        return False

    return True


def select_random_string():
    # We want non-repeating randomness for our random choice
    random.seed(None)

    content = open("17.txt", "r").read()
    lines = content.split("\n")

    return random.choice(lines)


def deterministic_random_key():
    random.seed(531)
    return [random.getrandbits(8) for _ in range(16)]


def deterministic_random_iv():
    random.seed(602)
    return [random.getrandbits(8) for _ in range(16)]


def attack_padding_oracle(oracle):
    ciphertext, iv = get_ciphertext_and_iv()
    blocks = [bytes(iv)] + challenge_7.as_blocks(ciphertext, 16)
    plaintext = b""

    for i in range(len(blocks)-1, 0, -1):
        block_p = b""  # Recovered plaintext of current block

        for j in range(15, -1, -1):
            cprime_k = b""  # Last k bytes of C′, the block we control
            pkcs = 16-j     # PKCS#7 padding char (our P′ value)

            for k in range(15-j):
                #    P′ᵢ[k] = Pᵢ[k]  ⊕ Cᵢ₋₁[k] ⊕ C′[k]
                # => C′[k]  = P′ᵢ[k] ⊕ Pᵢ[k]   ⊕ Cᵢ₋₁[k]
                cprime_k = bytes([pkcs ^ block_p[k] ^ blocks[i-1][15-k]]) + \
                    cprime_k

            for k in range(256):
                padding = b"0" * j
                guess = bytes([k])
                c_prime = padding + guess + cprime_k

                # If C′||Cᵢ has valid padding, we know C′[j]
                if oracle(c_prime + blocks[i]):
                    # We now have enough info to solve for Pᵢ[j] in
                    #
                    #    P′ᵢ[j] = Pᵢ[j]  ⊕ Cᵢ₋₁[j] ⊕ C′[j]
                    # => Pᵢ[j]  = P′ᵢ[j] ⊕ Cᵢ₋₁[j] ⊕ C′[j]
                    #
                    p_char = bytes([pkcs ^ blocks[i-1][j] ^ ord(guess)])
                    block_p += p_char
                    plaintext = p_char + plaintext
                    break

    return challenge_9.remove_pkcs7(plaintext, 16)


if __name__ == '__main__':
    print(attack_padding_oracle(padding_oracle))
