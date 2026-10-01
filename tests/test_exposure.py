import math
import unittest

from credverifier import exposure
from credverifier.exposure import Profile, assess


class ExposureTest(unittest.TestCase):
    def test_more_exposure_needs_more_entropy(self):
        bits = [assess(Profile(exposure=e, rotation_days=90)).required_bits
                for e in ("isolated", "internal", "partner", "internet")]
        self.assertEqual(bits, sorted(bits))
        self.assertLess(bits[0], bits[-1])

    def test_more_privilege_needs_more_entropy_and_length(self):
        results = [assess(Profile(privilege=p, rotation_days=90))
                   for p in ("standard", "elevated", "privileged", "critical")]
        self.assertEqual([r.required_bits for r in results], sorted(r.required_bits for r in results))
        self.assertEqual([r.min_length_floor for r in results], [12, 14, 16, 20])

    def test_lockout_reduces_online_requirement(self):
        open_ = assess(Profile(hash_storage="none"))
        locked = assess(Profile(hash_storage="none", lockout_threshold=5, lockout_minutes=30))
        self.assertLess(locked.online_bits, open_.online_bits)
        self.assertAlmostEqual(locked.online_guesses_per_second, 5 / 1800)

    def test_admin_unlock_lockout(self):
        p = Profile(lockout_threshold=3, lockout_minutes=0)
        self.assertAlmostEqual(exposure.online_rate(p), 3 / 86400)

    def test_rate_limit(self):
        self.assertAlmostEqual(exposure.online_rate(Profile(rate_limit_per_minute=6)), 0.1)

    def test_mfa_relaxes_online_only(self):
        base = assess(Profile(hash_storage="fast", rotation_days=90))
        mfa = assess(Profile(hash_storage="fast", mfa=True, rotation_days=90))
        self.assertLess(mfa.online_bits, base.online_bits)
        self.assertEqual(mfa.offline_bits, base.offline_bits)

    def test_slow_hash_needs_less_than_fast(self):
        fast = assess(Profile(hash_storage="fast", rotation_days=90))
        slow = assess(Profile(hash_storage="slow", rotation_days=90))
        self.assertLess(slow.required_bits, fast.required_bits)
        self.assertIn("offline", fast.driver)

    def test_longer_rotation_needs_more_entropy(self):
        short = assess(Profile(rotation_days=30))
        long = assess(Profile(rotation_days=365))
        self.assertGreater(long.required_bits, short.required_bits)

    def test_rotation_tiers(self):
        worst = assess(Profile(exposure="internet", privilege="critical", hash_storage="plaintext", shared_with=10))
        best = assess(Profile(exposure="isolated", privilege="standard", hash_storage="slow",
                              mfa=True, lockout_threshold=5, monitored=True))
        self.assertEqual(worst.rotation_days, 30)
        self.assertEqual(best.rotation_days, 365)

    def test_plaintext_caps_rotation_and_warns(self):
        a = assess(Profile(exposure="isolated", privilege="standard", hash_storage="plaintext",
                           mfa=True, lockout_threshold=5, monitored=True))
        self.assertLessEqual(a.rotation_days, 30)
        self.assertTrue(any("clear text" in n for n in a.notes))

    def test_lengths_respect_floor_and_bits(self):
        a = assess(Profile(exposure="internet", privilege="critical", hash_storage="fast"))
        for name, size in exposure.CHARSETS:
            self.assertGreaterEqual(a.lengths[name], a.min_length_floor)
            self.assertGreaterEqual(a.lengths[name] * math.log2(size), a.required_bits)

    def test_invalid_profile(self):
        with self.assertRaises(ValueError):
            assess(Profile(exposure="moon"))
        with self.assertRaises(ValueError):
            assess(Profile(shared_with=0))

    def test_human_duration(self):
        self.assertEqual(exposure.human_duration(None), "n/a")
        self.assertEqual(exposure.human_duration(0.5), "< 1 second")
        self.assertEqual(exposure.human_duration(90), "1.5 minutes")
        self.assertIn("years", exposure.human_duration(1e20))

    def test_cli_runs(self):
        import contextlib
        import io
        import json

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(exposure.main(["--exposure", "internet", "--json"]), 0)
        data = json.loads(buf.getvalue())
        self.assertIn("required_bits", data)


if __name__ == "__main__":
    unittest.main()
