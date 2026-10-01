"""Exact entropy of randomly generated passwords under complexity rules.

A password that is drawn uniformly at random from the set of all strings that
satisfy a policy has entropy log2(|set|). Naively using
``length * log2(alphabet)`` overstates the strength once minimum-count rules
("at least 2 digits") or first-character rules are applied, because those
rules shrink the set. This module counts the set exactly.

Counting uses exponential generating functions: for character classes of size
s_i with minimum counts m_i, the number of strings of length L is

    L! * [x^L]  prod_i ( e^(s_i x) - sum_{k < m_i} (s_i x)^k / k! )

Classes must be disjoint (upper, lower, digits, symbols are).
"""

from __future__ import annotations

import math
from fractions import Fraction
from functools import lru_cache
from typing import Sequence


def _class_series(size: int, minimum: int, degree: int) -> list[Fraction]:
    """Truncated EGF coefficients of sum_{k >= minimum} (size*x)^k / k!."""
    coeffs = []
    for k in range(degree + 1):
        if k < minimum:
            coeffs.append(Fraction(0))
        else:
            coeffs.append(Fraction(size**k, math.factorial(k)))
    return coeffs


def _multiply(a: list[Fraction], b: list[Fraction], degree: int) -> list[Fraction]:
    out = [Fraction(0)] * (degree + 1)
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j in range(degree + 1 - i):
            if b[j]:
                out[i + j] += ai * b[j]
    return out


@lru_cache(maxsize=1024)
def _count(length: int, classes: tuple[tuple[int, int], ...]) -> int:
    if length < 0:
        return 0
    poly = [Fraction(0)] * (length + 1)
    poly[0] = Fraction(1)
    for size, minimum in classes:
        poly = _multiply(poly, _class_series(size, minimum, length), length)
    value = poly[length] * math.factorial(length)
    assert value.denominator == 1
    return int(value)


def count_passwords(
    length: int,
    classes: Sequence[tuple[int, int]],
    first_allowed: Sequence[int] | None = None,
) -> int:
    """Number of distinct passwords satisfying a policy.

    Args:
        length: password length.
        classes: ``(class_size, minimum_count)`` per disjoint character class.
        first_allowed: optional count of characters in each class that may
            appear in the first position (same order as ``classes``). ``None``
            means any character may come first.
    """
    if first_allowed is not None and len(first_allowed) != len(classes):
        raise ValueError("first_allowed must have one entry per class")
    if length <= 0:
        return 0
    if any(s <= 0 and m > 0 for s, m in classes):
        return 0
    if first_allowed is None:
        return _count(length, tuple((int(s), int(m)) for s, m in classes if s > 0))

    pairs = [((int(s), int(m)), int(a)) for (s, m), a in zip(classes, first_allowed) if s > 0]
    classes = tuple(c for c, _ in pairs)
    first_allowed = [a for _, a in pairs]
    total = 0
    for idx, ((size, minimum), allowed) in enumerate(zip(classes, first_allowed)):
        if allowed <= 0:
            continue
        rest = list(classes)
        rest[idx] = (size, max(minimum - 1, 0))
        total += allowed * _count(length - 1, tuple(rest))
    return total


def entropy_bits(
    length: int,
    classes: Sequence[tuple[int, int]],
    first_allowed: Sequence[int] | None = None,
) -> float:
    """log2 of :func:`count_passwords`; 0.0 if no password satisfies the policy."""
    n = count_passwords(length, classes, first_allowed)
    return math.log2(n) if n > 0 else 0.0
