# Challenge 22 - Crack an MT19937 seed
#
# https://cryptopals.com/sets/3/challenges/22

import random
import time
import challenge_21


def generate_seed():
    time.sleep(random.randint(40, 1001))
    return int(time.time())


def random_number():
    seed = generate_seed()
    rand = challenge_21.MT19937(seed)
    time.sleep(random.randint(10, 101))

    return seed, rand.extract_number()


def crack_seed(output):
    """
    Guesses a PRNG seed that is based on a recent timestamp.
    """
    now = int(time.time())

    for seed in range((now - 1103), now):
        result = challenge_21.MT19937(seed).extract_number()

        if result == output:
            return True, seed

    return False, 0

if __name__ == '__main__':
    seed, output = random_number()

    print("Random number is {}".format(output))
    print("Attempting to crack seed...")

    success, recovered_seed = crack_seed(output)

    if success and recovered_seed == seed:
        print("Seed was successfully cracked as {}".format(recovered_seed))
