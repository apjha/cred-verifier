"""Check that cred-toolkit.html computes the same numbers as the Python package.

Runs the page's pure-logic <script id="core"> block under Node. Skipped when
Node is not installed.
"""

import itertools
import json
import os
import re
import shutil
import subprocess
import unittest

from credverifier import exposure
from credverifier.entropy import count_passwords
from credverifier.passgen import Policy

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = os.path.join(ROOT, "cred-toolkit.html")

RUNNER = r"""
const fs = require("fs"), vm = require("vm");
const html = fs.readFileSync(process.argv[1], "utf8");
const core = html.match(/<script id="core">([\s\S]*?)<\/script>/)[1];
const ctx = { crypto: globalThis.crypto, console };
vm.createContext(ctx);
vm.runInContext(core + "\nthis.CredCore = CredCore;", ctx);
const C = ctx.CredCore;
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const out = { assessments: [], counts: [], policies: [], samples: [] };
for (const p of input.profiles) out.assessments.push(C.assess(p));
for (const [len, classes, first] of input.counts) out.counts.push(C.countPasswords(len, classes, first).toString());
for (const pol of input.policies) {
  out.policies.push({ bits: C.policyEntropy(pol), lengthFor80: C.lengthForBits(pol, 80, 0) });
  out.samples.push(Array.from({ length: 50 }, () => C.generate(pol)));
}
process.stdout.write(JSON.stringify(out));
"""


def js_profile(p: exposure.Profile) -> dict:
    return {
        "exposure": p.exposure, "privilege": p.privilege, "lockoutThreshold": p.lockout_threshold,
        "lockoutMinutes": p.lockout_minutes, "rateLimit": p.rate_limit_per_minute, "mfa": p.mfa,
        "hash": p.hash_storage, "attacker": p.attacker, "sharedWith": p.shared_with,
        "monitored": p.monitored, "rotationDays": p.rotation_days,
    }


def js_policy(p: Policy) -> dict:
    return {
        "length": p.length, "upper": p.upper, "lower": p.lower, "digits": p.digits, "symbols": p.symbols,
        "minUpper": p.min_upper, "minLower": p.min_lower, "minDigits": p.min_digits, "minSymbols": p.min_symbols,
        "symbolSet": p.symbol_set, "exclude": p.exclude, "noAmbiguous": p.no_ambiguous,
        "startWithLetter": p.start_with_letter, "excelSafe": p.excel_safe,
    }


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class HtmlParityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        profiles = [
            exposure.Profile(exposure=e, privilege=pr, hash_storage=h, mfa=m, lockout_threshold=lt,
                             lockout_minutes=lm, monitored=mon, shared_with=sw, attacker=at, rotation_days=rd)
            for e, pr, h, m, (lt, lm), mon, sw, at, rd in itertools.islice(itertools.product(
                exposure.EXPOSURE, exposure.PRIVILEGE, exposure.HASH_STORAGE, (False, True),
                ((0, 30), (5, 30), (3, 0)), (False, True), (1, 7), exposure.ATTACKER, (None, 400)), 0, None, 7)
        ]
        profiles.append(exposure.Profile(rate_limit_per_minute=6))
        cls.profiles = profiles

        cls.counts = [
            (12, [[26, 1], [26, 1], [10, 1], [28, 1]], None),
            (20, [[26, 2], [26, 2], [10, 3], [28, 2]], [26, 26, 10, 20]),
            (5, [[3, 2], [2, 1]], [0, 2]),
            (40, [[26, 0], [10, 5]], None),
        ]
        cls.policies = [
            Policy(),
            Policy(length=24, min_digits=3, min_symbols=2, no_ambiguous=True, start_with_letter=True),
            Policy(length=12, symbols=False, min_symbols=0, exclude="xyz"),
            Policy(length=10, symbol_set="=+-@#", excel_safe=True),
        ]
        payload = {
            "profiles": [js_profile(p) for p in profiles],
            "counts": [list(c) for c in cls.counts],
            "policies": [js_policy(p) for p in cls.policies],
        }
        res = subprocess.run(["node", "-e", RUNNER, HTML], input=json.dumps(payload),
                             capture_output=True, text=True, check=True)
        cls.js = json.loads(res.stdout)

    def test_enough_profiles(self):
        self.assertGreater(len(self.profiles), 500)

    def test_assessments_match(self):
        for p, js in zip(self.profiles, self.js["assessments"]):
            py = exposure.assess(p)
            with self.subTest(profile=p):
                self.assertEqual(js["requiredBits"], py.required_bits)
                self.assertEqual(js["rotationDays"], py.rotation_days)
                self.assertEqual(js["recommendedRotationDays"], py.recommended_rotation_days)
                self.assertEqual(js["riskScore"], py.risk_score)
                self.assertEqual(js["riskFactors"], py.risk_factors)
                self.assertEqual(js["lengths"], py.lengths)
                self.assertEqual(js["passphraseWords"], py.passphrase_words)
                self.assertEqual(js["minLengthFloor"], py.min_length_floor)
                self.assertEqual(js["notes"], py.notes)
                self.assertEqual(js["driver"], py.driver)
                self.assertAlmostEqual(js["onlineBits"], py.online_bits, delta=0.051)
                self.assertAlmostEqual(js["offlineBits"], py.offline_bits, delta=0.051)

    def test_counts_match_exactly(self):
        for (length, classes, first), js in zip(self.counts, self.js["counts"]):
            self.assertEqual(int(js), count_passwords(length, [tuple(c) for c in classes], first))

    def test_policy_entropy_and_length_match(self):
        from credverifier.passgen import length_for_bits

        for pol, js in zip(self.policies, self.js["policies"]):
            self.assertAlmostEqual(js["bits"], pol.entropy_bits(), places=6)
            self.assertEqual(js["lengthFor80"], length_for_bits(pol, 80, 0))

    def test_generated_samples_follow_policy(self):
        for pol, samples in zip(self.policies, self.js["samples"]):
            classes = pol.classes()
            first = "".join(c for _, chars, _ in classes for c in chars if pol.first_char_filter(c))
            alphabet = "".join(chars for _, chars, _ in classes)
            for pw in samples:
                self.assertEqual(len(pw), pol.length)
                self.assertIn(pw[0], first)
                self.assertTrue(set(pw) <= set(alphabet))
                for _, chars, minimum in classes:
                    self.assertGreaterEqual(sum(c in chars for c in pw), minimum)

    def test_human_duration_matches(self):
        # Same formatting rules on both sides for the values shown in the UI.
        values = [None, 0.5, 90, 7200, 5e6, 3e8, 1e15, 1e40]
        script = (
            "const fs=require('fs'),vm=require('vm');"
            "const h=fs.readFileSync(process.argv[1],'utf8').match(/<script id=\"core\">([\\s\\S]*?)<\\/script>/)[1];"
            "const c={};vm.createContext(c);vm.runInContext(h+';this.C=CredCore',c);"
            "process.stdout.write(JSON.stringify(JSON.parse(fs.readFileSync(0,'utf8')).map(v=>c.C.humanDuration(v))))"
        )
        res = subprocess.run(["node", "-e", script, HTML], input=json.dumps(values),
                             capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(res.stdout), [exposure.human_duration(v) for v in values])


if __name__ == "__main__":
    unittest.main()
