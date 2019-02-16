# Challenge 28 - Implement a SHA-1 keyed MAC
#
# https://cryptopals.com/sets/4/challenges/28
#
# Implementation of SHA-1 based on FIPS-180-4.

import unittest


class SHA1:
    block_size = 64
    word_size = 32

    def __init__(self, msg):
        # 32-bit words of the initial hash value, H⁽⁰⁾
        self.h0 = 0x67452301
        self.h1 = 0xefcdab89
        self.h2 = 0x98badcfe
        self.h3 = 0x10325476
        self.h4 = 0xc3d2e1f0

        # Append padding to the message
        msg += self.__calculate_padding(msg)

        # Split the message into blocks and process them
        for block in self.__prepare_blocks(msg):
            self.__process_block(block)

    def hexdigest(self):
        """
        Returns the digest in hexadecimal format.
        """
        digest = ""
        digest += hex(self.h0)[2:].rjust(8, '0')
        digest += hex(self.h1)[2:].rjust(8, '0')
        digest += hex(self.h2)[2:].rjust(8, '0')
        digest += hex(self.h3)[2:].rjust(8, '0')
        digest += hex(self.h4)[2:].rjust(8, '0')

        return digest

    def __calculate_padding(self, msg):
        """
        Calculates a message padding, which is equal to the following (in
        bits):

        l := the length of the message
        k := the smallest non-negative solution in (l+1+k ≡ 448 mod 512)
        padding := 1 || k zero bits || l
        """
        padding_len = (56 - (len(msg) + 1 % self.block_size)) % self.block_size
        msg_len = i32_to_i64(len(msg))
        padding = b"\x80" + (b"\x00" * padding_len) + msg_len

        return padding

    def __prepare_blocks(self, msg):
        """
        Splits a message up into 512-bit blocks, with 16 words per block and
        4 bytes by word.
        """
        blocks = []
        n_blocks = len(msg) // self.block_size

        # 512 bits per block
        bits_per_block = self.block_size * 8
        # 16 words per block
        words_per_block = bits_per_block // self.word_size
        # 4 bytes per word
        bytes_per_word = self.block_size // words_per_block

        for i in range(n_blocks):
            new_block = []

            for j in range(words_per_block):
                n = 0

                for k in range(bytes_per_word):
                    offset = (i * self.block_size) + (j * bytes_per_word) + k
                    n <<= 8
                    n += msg[offset]

                new_block.append(n)

            blocks.append(new_block)

        return blocks

    def __process_block(self, block):
        """
        Processes a message block using a message schedule (W).
        """
        w = block[:]

        # 0 ≤ t ≤ 15 is H⁽ᶦ⁾ⱼ, so we only need to prepare 16 ≤ t ≤ 79
        for t in range(16, 80):
            w_t = i32(self.__rotl(1, w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]))
            w.append(w_t)

        # Initialize the working variables
        a = self.h0
        b = self.h1
        c = self.h2
        d = self.h3
        e = self.h4

        # Based on t, lookup the k constant, apply fₜ(x,y,z), and modify the
        # working variables accordingly
        for t in range(80):
            if t <= 19:
                k = 0x5a827999
                f = (b & c) ^ (~b & d)
            elif t <= 39:
                k = 0x6ed9eba1
                f = b ^ c ^ d
            elif t <= 59:
                k = 0x8f1bbcdc
                f = (b & c) ^ (b & d) ^ (c & d)
            else:
                k = 0xca62c1d6
                f = b ^ c ^ d

            t2 = i32(self.__rotl(5, a) + f + e + k + w[t])
            e = d
            d = c
            c = i32(self.__rotl(30, b))
            b = a
            a = t2

        # Compute the i-th intermediate hash value H⁽ᶦ⁾
        self.h0 = i32(a + self.h0)
        self.h1 = i32(b + self.h1)
        self.h2 = i32(c + self.h2)
        self.h3 = i32(d + self.h3)
        self.h4 = i32(e + self.h4)

    def __rotl(self, n, x):
        """
        Rotate left as an unsigned 32-bit integer.
        """
        return (x << n) | (x >> self.word_size - n)


def i32(i):
    return i & 0xffffffff


def i32_to_i64(i):
    """
    Coverts an unsigned 32-bit integer to an unsigned 64-bit integer.
    """
    result = b""

    # Obtain a hex string representation of i as a 64-bit integer by justifying
    # the text to 16 characters
    i64 = ("%x" % (i * 8)).rjust(16, '0')

    # Build the result by enumerating over each byte (2 hex characters)
    for k in range(0, 16, 2):
        next_byte = i64[k:k+2]
        result += bytes([int(next_byte, 16)])

    return result


class Challenge28(unittest.TestCase):
    def test_sha1(self):
        self.assertEqual(SHA1(b"hello world").hexdigest(),
                         "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")

    def test_sha1_mac(self):
        self.assertNotEqual(SHA1_MAC(b"s3cr3t", b"hello world"),
                            SHA1_MAC(b"s3cr3t", b"goodbye world"))
        self.assertNotEqual(SHA1_MAC(b"s3cr3t", b"hello world"),
                            SHA1_MAC(b"AAAAAA", b"hello world"))


def SHA1_MAC(key, msg):
    return SHA1(key + msg).hexdigest()


if __name__ == '__main__':
    unittest.main()
