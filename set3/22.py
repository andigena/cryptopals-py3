import random
import time

from set3.utilz import MT19937


def routine():
    def simulate_time(lower, upper):
        return random.randint(lower, upper)

    timestamp = int(time.time())
    wait1 = simulate_time(40, 1000)
    seed = timestamp + wait1
    mt = MT19937(seed)
    wait2 = simulate_time(40, 1000)

    return timestamp, timestamp + wait1 + wait2, mt.extract_number(), seed


start, end, output, seed = routine()

# brute
for guess in range(start, end + 1):
    mt = MT19937(guess)
    if mt.extract_number() == output:
        print('Found seed: {}'.format(guess))
        assert guess == seed
        break
