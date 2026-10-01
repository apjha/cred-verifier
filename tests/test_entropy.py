import itertools
import math
import unittest

from credverifier.entropy import count_passwords, entropy_bits


def brute_force(length, classes, first_allowed=None):
    """Enumerate every string over small alphabets and count the valid ones."""
    alphabet = []
    for idx, (size, _) in enumerate(classes):
        alphabet += [(idx, j) for j in range(size)]
    total = 0
    for combo in itertools.product(alphabet, repeat=length):
        if first_allowed is not None:
            cls, j = combo[0]
            if j >= first_allowed[cls]:
                continue
        if all(sum(1 for c, _ in combo if c == i) >= m for i, (_, m) in enumerate(classes)):
            total += 1
    return total


class CountTest(unittest.TestCase):
    def test_no_minimums_is_alphabet_power(self):
        self.assertEqual(count_passwords(8, [(26, 0), (10, 0)]), 36**8)

    def test_matches_brute_force(self):
        cases = [
            (4, [(2, 1), (3, 1)]),
            (5, [(2, 2), (2, 1), (1, 0)]),
            (4, [(3, 0), (2, 3)]),
            (3, [(2, 1), (2, 1), (2, 1)]),
        ]
        for length, classes in cases:
            with self.subTest(length=length, classes=classes):
                self.assertEqual(count_passwords(length, classes), brute_force(length, classes))

    def test_first_character_restriction_matches_brute_force(self):
        cases = [
            (4, [(2, 1), (3, 1)], [2, 0]),
            (4, [(3, 1), (2, 1), (2, 0)], [1, 2, 0]),
        ]
        for length, classes, first in cases:
            with self.subTest(length=length, classes=classes, first=first):
                self.assertEqual(count_passwords(length, classes, first), brute_force(length, classes, first))

    def test_impossible_policy(self):
        self.assertEqual(count_passwords(2, [(5, 2), (5, 1)]), 0)
        self.assertEqual(entropy_bits(2, [(5, 2), (5, 1)]), 0.0)

    def test_minimums_reduce_entropy(self):
        plain = 16 * math.log2(94)
        self.assertLess(entropy_bits(16, [(26, 1), (26, 1), (10, 1), (32, 1)]), plain)


if __name__ == "__main__":
    unittest.main()
