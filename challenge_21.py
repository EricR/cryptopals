# Challenge 21 - Implement the MT19937 Mersenne Twister RNG
#
# https://cryptopals.com/sets/3/challenges/21

import unittest


class MT19937:
    # Word size in bits (w)
    word_size = 32

    # Degree of recurrence (n), or the number of words in the state array
    recurrence_deg = 624

    # Middle word (m), an offset used in the recurrence relation defining the
    # series
    middle_word = 397

    # Separation point of one word (r)
    separation_point = 31

    # Constants used in A (a)
    a_constants = 0x9908b0df

    # TGFSR(R) tempering bit mask (b)
    bitmask_b = 0x9d2c5680

    # TGFSR(R) tempering bit mask (c)
    bitmask_c = 0xefc60000

    # Additional tempering bit mask to improve lower-bit equidistribution (d)
    bitmask_d = 0xffffffff

    # Additional tempering bit shift to improve lower-bit equidistribution (l)
    bitshift_l = 18

    # TGFSR(R) tempering bit shift (s)
    bitshift_s = 7

    # TGFSR(R) tempering bit shift (t)
    bitshift_t = 15

    # Additional tempering bit shift to improve lower-bit equidistribution (u)
    bitshift_u = 11

    # MT19937 F constant
    f = 1812433253

    # Bit mask constants
    lower_mask = 0x7fffffff  # Least significant r bits
    upper_mask = 0x80000000  # Most significant w-r bits

    # Generator state
    state = [0 for _ in range(recurrence_deg)]

    # Index value
    idx = 0

    def __init__(self, seed=5489):
        self.state[0] = seed

        # Initialize the state based on the seed
        for i in range(1, self.recurrence_deg):
            prev = self.state[i-1]
            prev_shifted = prev >> (self.word_size - 2)

            self.state[i] = int32(self.f * (prev ^ prev_shifted) + i)

        # Immediately call twist() to generate the first series of random
        # numbers
        self.twist()

    def extract_number(self):
        """
        Extracts a seemingly random number based on state[idx] and applies a
        tempering transform. When there are no more numbers left to generate
        from the state, calls twist() to generate a new state.
        """
        if self.idx >= self.recurrence_deg:
            self.twist()

        # Apply the tempering transform
        y = self.state[self.idx]
        y ^= y >> self.bitshift_u & self.bitmask_d
        y ^= y << self.bitshift_s & self.bitmask_b
        y ^= y << self.bitshift_t & self.bitmask_c
        y ^= y >> self.bitshift_l

        self.idx += 1

        return int32(y)

    def twist(self):
        """
        Applies a twist transformation to generate the next n (recurrence_deg)
        numbers in the series, which becomes the new state.

        The series is defined by the following linear recurrence equation:

        Xₖ₊ₙ = Xₖ₊ₘ ⊕ ((Xᵘₖ || Xˡₖ₊₁) A)

        Where:
        - A is a constant matrix
        - Xᵘₖ are the upper (leftmost) w-r bits of Xₖ
        - Xˡₖ₊₁ are the lower (rightmost) r bits of Xₖ₊₁
        """
        for k in range(self.recurrence_deg):
            x_km = self.state[(k + self.middle_word) % self.recurrence_deg]
            x_uk = self.state[k] & self.upper_mask
            x_lk = self.state[(k+1) % self.recurrence_deg] & self.lower_mask

            # Since we're using rational normal form, multiplication can be
            # simplified as defined by xA
            xA = (x_uk + x_lk) >> 1

            # Add A to xA iff lowest bit of (Xᵘₖ || Xˡₖ₊₁) is 1
            if (x_uk + x_lk) % 2 != 0:
                xA ^= self.a_constants

            self.state[k] = x_km ^ xA

        self.idx = 0


class Challenge21(unittest.TestCase):
    def test_MT19937(self):
        random = MT19937(123)
        self.assertEqual(random.extract_number(), 2991312382)
        self.assertEqual(random.extract_number(), 3062119789)
        self.assertEqual(random.extract_number(), 1228959102)
        self.assertEqual(random.extract_number(), 1840268610)


def int32(x):
    """
    Returns the lowest w (32) bits of a given value.
    """
    return x & 0xffffffff

if __name__ == '__main__':
    unittest.main()
