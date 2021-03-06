# Challenge 1 - Convert hex to base64
#
# https://cryptopals.com/sets/1/challenges/1

import unittest
import base64


class Challenge1(unittest.TestCase):
    def test_convert_hex_to_base64(self):
        result = hex_to_base64(
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f"
            + "69736f6e6f7573206d757368726f6f6d")

        self.assertEqual(result,
                         "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3V"
                         + "zIG11c2hyb29t")


def hex_to_base64(str1):
    return base64.b64encode(bytes.fromhex(str1)).decode()


if __name__ == '__main__':
    unittest.main()
