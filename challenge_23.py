# Challenge 23 - Clone an MT19937 RNG from its output
#
# https://cryptopals.com/sets/3/challenges/23

import unittest
import random
import challenge_21


class MT19937Cloner(challenge_21.MT19937):
    def sample(self, y):
        if self.idx <= self.recurrence_deg:
            self.state[self.idx] = self.untemper(y)
            self.idx += 1

    def untemper(self, y):
        """
        Applies the inverse of MT19937's tempering function, following that:

        - The inverse of XOR is XOR.
        - There's no immediate inverse of shifting then masking bits. To
          recover the original bits, we repeat the operations and then add an
          additional mask equal to the number of bits shifted. This procedure
          is repeated, shifting the additional mask, until all 32 bits have
          been accounted for.
        """
        y ^= y >> self.bitshift_l

        # bitshift_t = 15
        # bitmask_c = 0xefc60000
        #                   ~~~~ This will never result in 1 when AND'd,
        #                        meaning we could optimize here by skipping
        #                        the first 16 bits (when i = 0)
        # additional mask = 0xfffe (15 bits)
        # 32 // 15 = 3 times
        #
        for i in range(1, 3):
            shifted_mask = 0xfffe << (self.bitshift_t * i)
            y ^= y << self.bitshift_t & (self.bitmask_c & shifted_mask)

        # bitshift_s = 7
        # bitmask_b = 0x9d2c5680
        # additional mask = 0xfe (7 bits)
        # 32 // 7 = 5 times
        #
        for i in range(5):
            shifted_mask = 0xfe << (self.bitshift_s * i)
            y ^= y << self.bitshift_s & (self.bitmask_b & shifted_mask)

        # bitshift_u = 11
        # bitmask_d = 0xffffffff
        #             ~~~~~~~~~~ This cancels out when AND'd
        # additional mask = 0x7ff (11 bits)
        # 32 // 11 = 3 times
        #
        for i in range(2, -1, -1):
            shifted_mask = 0x7ff << (self.bitshift_u * i)
            y ^= y >> self.bitshift_u & shifted_mask

        return challenge_21.int32(y)


class Challenge23(unittest.TestCase):
    def test_untemper(self):
        cloner = MT19937Cloner()

        # Original MT19937 tempering function for testing
        def temper(y):
            y ^= y >> cloner.bitshift_u & cloner.bitmask_d
            y ^= y << cloner.bitshift_s & cloner.bitmask_b
            y ^= y << cloner.bitshift_t & cloner.bitmask_c
            y ^= y >> cloner.bitshift_l

            return challenge_21.int32(y)

        # Randomized testing to ensure that untempering works correctly
        for _ in range(100000):
            x = random.randint(0, 0xffffff)
            y = temper(x)
            self.assertEqual(cloner.untemper(y), x)

    def test_sample(self):
        seed = random.randint(0, 0xffffff)
        mt = challenge_21.MT19937(seed)
        cloner = MT19937Cloner()

        # Sample enough observed outputs to recreate the generator's state
        for _ in range(mt.recurrence_deg):
            observed = mt.extract_number()
            cloner.sample(observed)

        # Make sure our "spliced" generator matches the original
        for i in range(1000):
            self.assertEqual(cloner.extract_number(), mt.extract_number())

if __name__ == '__main__':
    unittest.main()
