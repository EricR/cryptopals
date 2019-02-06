# Challenge 5 - Implement repeating-key XOR
#
# https://cryptopals.com/sets/1/challenges/5

import unittest


class Challenge5(unittest.TestCase):
    def test_repeating_xor(self):
        key = b"ICE"
        plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy "
        plaintext += b"when I hear a cymbal"

        self.assertEqual(repeating_xor(key, plaintext).hex(),
                         "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d62"
                         + "3d63343c2a26226324272765272a282b2f20430a652e2c"
                         + "652a3124333a653e2b2027630c692b202831652863263"
                         + "02e27282f")


def rotate(items):
    return items[1:] + items[:1]


def repeating_xor(key, plaintext):
    output = bytearray()

    for i in range(len(plaintext)):
        output.append(plaintext[i] ^ key[0])
        key = rotate(key)

    return bytes(output)


if __name__ == '__main__':
    unittest.main()
