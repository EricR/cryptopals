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
    now = int(time.time())

    for seed in range((now - 1103), now):
        result = challenge_21.MT19937(seed).extract_number()

        if result == output:
            return seed

    return False

if __name__ == '__main__':
    seed, output = random_number()

    print("Random number is {}".format(output))
    print("Attempting to crack seed...")

    recovered_seed = crack_seed(output)

    print("Seed was {}".format(recovered_seed))

    if recovered_seed == seed:
        print("Seed was successfully cracked")
