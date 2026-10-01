import contextlib
import datetime as dt
import io
import math
import os
import random
import string
import tempfile
import unittest

from credverifier import exposure, passgen
from credverifier.passgen import Policy, PolicyError, generate


class PolicyTest(unittest.TestCase):
    def test_generated_passwords_meet_minimums(self):
        policy = Policy(length=12, min_upper=2, min_lower=2, min_digits=3, min_symbols=2)
        for _ in range(200):
            pw = generate(policy)
            self.assertEqual(len(pw), 12)
            self.assertGreaterEqual(sum(c.isupper() for c in pw), 2)
            self.assertGreaterEqual(sum(c.islower() for c in pw), 2)
            self.assertGreaterEqual(sum(c.isdigit() for c in pw), 3)
            self.assertGreaterEqual(sum(c in policy.symbol_set for c in pw), 2)

    def test_excel_safe_first_character(self):
        policy = Policy(length=4, upper=False, lower=False, digits=False,
                        min_upper=0, min_lower=0, min_digits=0, symbol_set="=+-@#")
        for _ in range(200):
            self.assertEqual(generate(policy)[0], "#")

    def test_start_with_letter(self):
        policy = Policy(length=8, start_with_letter=True)
        for _ in range(200):
            self.assertIn(generate(policy)[0], string.ascii_letters)

    def test_exclusions_and_ambiguous(self):
        policy = Policy(length=30, exclude="abcXYZ", no_ambiguous=True)
        banned = set("abcXYZ") | set(passgen.AMBIGUOUS)
        for _ in range(100):
            self.assertFalse(set(generate(policy)) & banned)

    def test_disabled_class_not_used(self):
        policy = Policy(length=20, symbols=False, min_symbols=0)
        for _ in range(100):
            self.assertTrue(generate(policy).isalnum())

    def test_minimums_exceeding_length(self):
        with self.assertRaises(PolicyError):
            Policy(length=3).validate()

    def test_required_class_emptied_by_exclusions(self):
        with self.assertRaises(PolicyError):
            Policy(exclude=string.digits).classes()

    def test_entropy_matches_simple_case(self):
        policy = Policy(length=10, upper=False, digits=False, symbols=False,
                        min_upper=0, min_lower=0, min_digits=0, min_symbols=0)
        self.assertAlmostEqual(policy.entropy_bits(), 10 * math.log2(26))

    def test_uniformity_smoke(self):
        # Alphabet {a, 0}, length 3, at least one of each: 6 valid strings.
        policy = Policy(length=3, upper=False, symbols=False, lower=True, digits=True,
                        min_upper=0, min_symbols=0, exclude=string.ascii_lowercase[1:] + string.digits[1:])
        self.assertEqual(policy.count(), 6)
        rng = random.Random(1)
        seen = {}
        for _ in range(6000):
            pw = generate(policy, rng)
            seen[pw] = seen.get(pw, 0) + 1
        self.assertEqual(len(seen), 6)
        for n in seen.values():
            self.assertTrue(800 < n < 1200)

    def test_length_for_bits(self):
        policy = Policy()
        length = passgen.length_for_bits(policy, 80, floor=0)
        policy.length = length
        self.assertGreaterEqual(policy.entropy_bits(), 80)
        policy.length = length - 1
        self.assertLess(policy.entropy_bits(), 80)


class OutputTest(unittest.TestCase):
    def test_rows_with_assessment(self):
        a = exposure.assess(exposure.Profile(rotation_days=30))
        policy = Policy(length=20)
        header, rows = passgen.build_rows(["x" * 20], ["root@db01"], policy, a, today=dt.date(2026, 1, 1))
        self.assertEqual(header[0], "Account")
        self.assertEqual(rows[0][0], "root@db01")
        self.assertEqual(rows[0][header.index("Rotate by")], "2026-01-31")
        self.assertEqual(rows[0][header.index("Meets policy")], "Yes")

    def test_formats(self):
        header, rows = ["#", "Password"], [["1", "a,b"], ["2", "c"]]
        self.assertEqual(passgen.format_rows(header, rows, "tsv"), "#\tPassword\n1\ta,b\n2\tc\n")
        self.assertIn('"a,b"', passgen.format_rows(header, rows, "csv"))
        self.assertNotIn("Password", passgen.format_rows(header, rows, "tsv", show_header=False))
        self.assertIn("| 1 | a,b      |", passgen.format_rows(header, rows, "table"))

    def test_cli_tsv(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rc = passgen.main(["-n", "5", "-l", "14", "--exposure", "internet", "--privilege", "standard"])
        self.assertEqual(rc, 0)
        lines = buf.getvalue().splitlines()
        self.assertEqual(len(lines), 6)
        self.assertEqual(len(lines[1].split("\t")[1]), 14)

    def test_cli_uses_framework_length(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            passgen.main(["-n", "1", "--no-header", "--exposure", "internet", "--privilege", "critical"])
        self.assertGreaterEqual(len(buf.getvalue().split("\t")[1]), 20)

    def test_output_file_is_private(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.tsv")
            with contextlib.redirect_stderr(io.StringIO()):
                passgen.main(["-n", "2", "-o", path])
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
