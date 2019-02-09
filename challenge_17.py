# Challenge 17 - The CBC padding oracle
#
# https://cryptopals.com/sets/3/challenges/17

import random
import challenge_07
import challenge_09
import challenge_10


def get_ciphertext_and_iv():
    key, iv = deterministic_random_key_and_iv()
    ciphertext = challenge_10.AES_CBC(key, iv).encrypt(select_random_string())

    return ciphertext, iv


def padding_oracle(ciphertext):
    key, iv = deterministic_random_key_and_iv()

    try:
        challenge_10.AES_CBC(key, iv).decrypt(ciphertext)
    except challenge_09.PaddingError:
        return False

    return True


def select_random_string():
    # We want non-repeating randomness for our random choice
    random.seed(None)

    content = open("17.txt", "rb").read()
    lines = content.split(b"\n")

    return random.choice(lines)


def deterministic_random_key_and_iv():
    random.seed(17)
    data = [random.getrandbits(8) for _ in range(32)]

    return data[:16], data[16:32]


def decrypt_with_padding_oracle(oracle):
    ciphertext, iv = get_ciphertext_and_iv()
    blocks = [bytes(iv)] + challenge_07.as_blocks(ciphertext, 16)
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

    return challenge_09.remove_pkcs7(plaintext, 16)


if __name__ == '__main__':
    print(decrypt_with_padding_oracle(padding_oracle).decode())
