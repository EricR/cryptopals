# Challenge 7 - AES in ECB mode
#
# https://cryptopals.com/sets/1/challenges/7
#
# Implementation of AES based on FIPS-197. Makes no effort to mitigate side-
# channel attacks, useful for educational purposes only.

import base64
import unittest

class AES():
    # Number of rounds per key length (Nr)
    rounds_per_keysize = {
        16: 10,
        24: 12,
        32: 14
    }

    # Number of 32-bit words in a key per key length (Nk)
    words_per_keysize = {
        16: 4,
        24: 6,
        32: 8
    }

    # The size of key expansions in bytes per key length
    expansion_per_keysize = {
        16: 176,
        24: 208,
        32: 240
    }

    # Number of columns (Nb), derived from the block size (always 128 bits)
    # divided by 32.
    nb = 4

    # Round constants (only need max 11 for AES-128, AES-192, and AES-256)
    rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    # S-box values
    s_box = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]

    # Inverted S-box values
    is_box = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d 
    ]

    def __init__(self, key):
        if len(key) not in self.rounds_per_keysize:
            raise ValueError("Invalid key size")

        self.nk = self.words_per_keysize[len(key)]
        self.nr = self.rounds_per_keysize[len(key)]
        self.state = [bytes(4) for row in range(self.nb)]
        self.key_schedule = self.__expand_key(key)

    def encrypt(self, plaintext):
        if len(plaintext) != 4 * self.nb:
            raise ValueError("Invalid block size")

        # Initial state is the provided plaintext
        self.state = as_blocks(list(plaintext), self.nb)

        # Add initial round key
        self.__add_round_key(0)

        # Apply rounds nr-1
        for i in range(1, self.nr):
            self.__sub_bytes()
            self.__shift_rows()
            self.__mix_columns()
            self.__add_round_key(i)

        # Apply last round
        self.__sub_bytes()
        self.__shift_rows()
        self.__add_round_key(self.nr)

        return bytes(sum(self.state, []))

    def decrypt(self, ciphertext):
        if len(ciphertext) != 4 * self.nb:
            raise ValueError("Invalid block size")

        # Initial state is the provided ciphertext
        self.state = as_blocks(list(ciphertext), self.nb)

        # Apply last round first
        self.__add_round_key(self.nr)
        self.__inv_shift_rows()
        self.__inv_sub_bytes()

        # Apply rounds nr-1 in reverse order
        for i in range(self.nr-1, 0, -1):
            self.__add_round_key(i)
            self.__inv_mix_columns()
            self.__inv_shift_rows()
            self.__inv_sub_bytes()

        # Add initial round key last
        self.__add_round_key(0)

        return bytes(sum(self.state, []))

    def __expand_key(self, key):
        """
        Prepares the key schedule (list of round keys) by expanding a given key.
        """
        tmp = bytearray(4)
        round_keys = bytearray(self.expansion_per_keysize[len(key)])

        # First round key is just the key itself
        for i, n in enumerate(key):
            round_keys[i] = n

        # Generate all other round keys (starting from nk, since we already
        # have our first key)
        for i in range(self.nk, self.nb * (self.nr+1)):
            # Get the previous 32-bit word and store it in tmp
            j = (i-1) * 4
            for k in range(4):
                tmp[k] = round_keys[j+k]

            if i % self.nk == 0:
                # Rotate tmp to the left
                rotate_word(tmp)

                # Substitute values of tmp by S-box values
                for k in range(4):
                    tmp[k] = self.s_box[tmp[k]]

                # Apply round constant to the first byte of tmp
                tmp[0] ^= self.rcon[int(i/self.nk)]

            # AES-256 (when nk == 8) applies the S-box a bit differently
            if self.nk == 8 and i % self.nk == 4:
                # Substitute values of tmp by S-box values
                for k in range(4):
                    tmp[k] = self.s_box[tmp[k]]

            # Add a new round key, which is equal to the XOR of the 32-bit word
            # Nk positions earlier (round_keys[k+m] below) and tmp
            j = i * 4
            k = (i - self.nk) * 4
            for m in range(4):
                round_keys[j+m] = round_keys[k+m] ^ tmp[m]

        return round_keys

    def __add_round_key(self, round_num):
        """
        Adds a given round key to the state by performing an XOR operation. Note
        that there is no inverse version of this function because the inverse is
        equivalent to itself.
        """
        for i in range(4):
            for j in range(self.nb):
                # Given a round number, state row (i), and state column (j),
                # determine the correct key schedule offset (k) and add the
                # round key bytes to the state
                k = (round_num * self.nb * 4) + (i * self.nb) + j
                self.state[i][j] ^= self.key_schedule[k]

    def __sub_bytes(self):
        """
        Substitutes state values with S-box values.
        """
        for i in range(4):
            for j in range(self.nb):
                self.state[i][j] = self.s_box[self.state[i][j]]

    def __shift_rows(self):
        """
        Applies a left shift to state rows where the number of shifts is equal
        to the row number.
        """
        self.state[0][1], self.state[1][1], self.state[2][1], self.state[3][1] = \
            self.state[1][1], self.state[2][1], self.state[3][1], self.state[0][1]
        self.state[0][2], self.state[1][2], self.state[2][2], self.state[3][2] = \
            self.state[2][2], self.state[3][2], self.state[0][2], self.state[1][2]
        self.state[0][3], self.state[1][3], self.state[2][3], self.state[3][3] = \
            self.state[3][3], self.state[0][3], self.state[1][3], self.state[2][3]

    def __mix_columns(self):
        """
        Applies a mixing function to the state columns.
        """
        for i in range(4):
            tmp = self.state[i][0] ^ self.state[i][1] ^ self.state[i][2] ^ self.state[i][3]
            first = self.state[i][0]

            self.state[i][0] ^= xtime(self.state[i][0] ^ self.state[i][1]) ^ tmp
            self.state[i][1] ^= xtime(self.state[i][1] ^ self.state[i][2]) ^ tmp
            self.state[i][2] ^= xtime(self.state[i][2] ^ self.state[i][3]) ^ tmp
            self.state[i][3] ^= xtime(self.state[i][3] ^ first) ^ tmp

    def __inv_sub_bytes(self):
        """
        Substitutes state values with inverse S-box values.
        """
        for i in range(4):
            for j in range(self.nb):
                self.state[i][j] = self.is_box[self.state[i][j]]

    def __inv_shift_rows(self):
        """
        Applies a right shift to state rows where the number of shifts is equal
        to the row number.
        """
        self.state[0][1], self.state[1][1], self.state[2][1], self.state[3][1] = \
            self.state[3][1], self.state[0][1], self.state[1][1], self.state[2][1]
        self.state[0][2], self.state[1][2], self.state[2][2], self.state[3][2] = \
            self.state[2][2], self.state[3][2], self.state[0][2], self.state[1][2]
        self.state[0][3], self.state[1][3], self.state[2][3], self.state[3][3] = \
            self.state[1][3], self.state[2][3], self.state[3][3], self.state[0][3]

    def __inv_mix_columns(self):
        """
        Applies an inverse mixing function to the state columns. Uses 
        preprocessing as described in Section 4.1.3 of The Design of Rijndael.
        The result is the same.
        """
        for i in range(4):
            u = xtime(xtime(self.state[i][0] ^ self.state[i][2]))
            v = xtime(xtime(self.state[i][1] ^ self.state[i][3]))

            self.state[i][0] ^= u
            self.state[i][1] ^= v
            self.state[i][2] ^= u
            self.state[i][3] ^= v

        self.__mix_columns()

class Challenge7(unittest.TestCase):
    def test_encrypt(self):
        cipher = AES(bytes.fromhex("10a58869d74be5a374cf867cfb473859"))
        ciphertext = cipher.encrypt(bytes.fromhex("00000000000000000000000000000000"))
        self.assertEqual(ciphertext, bytes.fromhex("6d251e6944b051e04eaa6fb4dbf78465"))

        cipher = AES(bytes.fromhex("e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd"))
        ciphertext = cipher.encrypt(bytes.fromhex("00000000000000000000000000000000"))
        self.assertEqual(ciphertext, bytes.fromhex("0956259c9cd5cfd0181cca53380cde06"))

        cipher = AES(bytes.fromhex("c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558"))
        ciphertext = cipher.encrypt(bytes.fromhex("00000000000000000000000000000000"))
        self.assertEqual(ciphertext, bytes.fromhex("46f2fb342d6f0ab477476fc501242c5f"))

    def test_decrypt(self):
        cipher = AES(bytes.fromhex("10a58869d74be5a374cf867cfb473859"))
        ciphertext = cipher.decrypt(bytes.fromhex("6d251e6944b051e04eaa6fb4dbf78465"))
        self.assertEqual(ciphertext, bytes.fromhex("00000000000000000000000000000000"))

        cipher = AES(bytes.fromhex("e9f065d7c13573587f7875357dfbb16c53489f6a4bd0f7cd"))
        ciphertext = cipher.decrypt(bytes.fromhex("0956259c9cd5cfd0181cca53380cde06"))
        self.assertEqual(ciphertext, bytes.fromhex("00000000000000000000000000000000"))

        cipher = AES(bytes.fromhex("c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558"))
        ciphertext = cipher.decrypt(bytes.fromhex("46f2fb342d6f0ab477476fc501242c5f"))
        self.assertEqual(ciphertext, bytes.fromhex("00000000000000000000000000000000"))

def as_blocks(data, size):
    """
    Breaks up a given list into blocks of a given size.
    """
    return [data[i:i + size] for i in range(0, len(data), size)]

def xtime(n):
    """
    Multiplies n by 2 in GF(2^8), which means we simply multiply by 2 and when
    an overflow would occur, we subtract (XOR) the product by 0x1b (AES'
    irreducible polynomial, denoted as m(x)) modulo 256.
    """
    if n < 128:
        # Already reduced form
        return n * 2
    else:
        # Need to reduce, so subtract (XOR) the product from m(x) mod 256
        return ((n * 2) ^ 0x1b) % 256

def rotate_word(word):
    """
    Rotates a list of 4 bytes to the left.
    """
    first = word[0]
    word[0] = word[1]
    word[1] = word[2]
    word[2] = word[3]
    word[3] = first

if __name__ == '__main__':
    cipher = AES(bytes("YELLOW SUBMARINE", 'ascii'))
    ciphertext_hex = open("7.txt", "r").read()
    ciphertext = base64.b64decode(ciphertext_hex)
    plaintext = ""

    for block in as_blocks(ciphertext, 16):
        plaintext += cipher.decrypt(block).decode()

    print(plaintext)
