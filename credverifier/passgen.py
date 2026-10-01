"""Bulk password generator with spreadsheet-friendly output.

Generates many passwords at once against custodian-supplied complexity rules
and prints them as a table. The default output is tab-separated, which pastes
straight into Excel / Google Sheets with one value per cell.

When an exposure profile is supplied (``--exposure ...``) the exposure
framework picks the length, reports whether the policy meets the requirement
and adds a "rotate by" date column.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import json
import math
import os
import secrets
import shutil
import string
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional, Sequence

from . import exposure
from .entropy import count_passwords

#: Symbols used by default: printable punctuation minus quotes, backslash and
#: backtick, which commonly break shells, scripts, connection strings and CSV.
DEFAULT_SYMBOLS = "!#$%&()*+,-./:;<=>?@[]^_{|}~"
#: Characters easily confused when read aloud or transcribed from a screen.
AMBIGUOUS = "Il1|O0o`'\""
#: Characters that make Excel treat a pasted cell as a formula (or swallow a
#: leading quote). Disallowed as the first character unless overridden.
EXCEL_UNSAFE_FIRST = "=+-@'\t\r\n "

DEFAULT_LENGTH = 16
#: Refuse policies where fewer than this fraction of random candidates pass.
MIN_ACCEPTANCE = 1e-5


class PolicyError(ValueError):
    pass


@dataclass
class Policy:
    length: int = DEFAULT_LENGTH
    upper: bool = True
    lower: bool = True
    digits: bool = True
    symbols: bool = True
    min_upper: int = 1
    min_lower: int = 1
    min_digits: int = 1
    min_symbols: int = 1
    symbol_set: str = DEFAULT_SYMBOLS
    exclude: str = ""
    no_ambiguous: bool = False
    start_with_letter: bool = False
    excel_safe: bool = True

    def classes(self) -> list[tuple[str, str, int]]:
        """Return ``(name, characters, minimum)`` for each enabled class."""
        removed = set(self.exclude) | (set(AMBIGUOUS) if self.no_ambiguous else set()) | set(" \t\r\n")
        spec = [
            ("upper", self.upper, string.ascii_uppercase, self.min_upper),
            ("lower", self.lower, string.ascii_lowercase, self.min_lower),
            ("digits", self.digits, string.digits, self.min_digits),
            ("symbols", self.symbols, self.symbol_set, self.min_symbols),
        ]
        out = []
        seen: set[str] = set()
        for name, enabled, chars, minimum in spec:
            if minimum < 0:
                raise PolicyError(f"minimum {name} cannot be negative")
            if not enabled:
                continue
            # Keep order, drop duplicates and characters already in an earlier class.
            kept = "".join(dict.fromkeys(c for c in chars if c not in removed and c not in seen))
            seen.update(kept)
            if not kept:
                if minimum:
                    raise PolicyError(f"no {name} characters left after exclusions, but {minimum} required")
                continue
            out.append((name, kept, minimum))
        if not out:
            raise PolicyError("no characters available - enable at least one character class")
        return out

    def first_char_filter(self, ch: str) -> bool:
        if self.start_with_letter and not ch.isalpha():
            return False
        if self.excel_safe and ch in EXCEL_UNSAFE_FIRST:
            return False
        return True

    def validate(self) -> None:
        classes = self.classes()
        if self.length < 1:
            raise PolicyError("length must be at least 1")
        required = sum(m for _, _, m in classes)
        if required > self.length:
            raise PolicyError(f"minimum character counts add up to {required}, more than length {self.length}")
        if self.count() == 0:
            raise PolicyError("no password can satisfy this policy")

    def _counts(self) -> tuple[list[tuple[int, int]], list[int]]:
        classes = self.classes()
        sizes = [(len(chars), m) for _, chars, m in classes]
        first = [sum(1 for c in chars if self.first_char_filter(c)) for _, chars, _ in classes]
        return sizes, first

    def count(self) -> int:
        sizes, first = self._counts()
        return count_passwords(self.length, sizes, first)

    def entropy_bits(self) -> float:
        n = self.count()
        return math.log2(n) if n else 0.0

    def alphabet(self) -> str:
        return "".join(chars for _, chars, _ in self.classes())

    def acceptance_rate(self) -> float:
        """Fraction of unconstrained candidates that satisfy the minimums."""
        sizes, first = self._counts()
        total = sum(s for s, _ in sizes)
        candidates = sum(first) * total ** (self.length - 1)
        return count_passwords(self.length, sizes, first) / candidates if candidates else 0.0


def length_for_bits(policy: Policy, bits: float, floor: int = 0, max_length: int = 256) -> int:
    """Shortest length (>= floor) at which ``policy`` reaches ``bits`` of entropy."""
    probe = Policy(**{**policy.__dict__})
    for length in range(max(floor, 1), max_length + 1):
        probe.length = length
        if sum(m for _, _, m in probe.classes()) > length:
            continue
        if probe.entropy_bits() >= bits:
            return length
    raise PolicyError(f"cannot reach {bits} bits within {max_length} characters with this character set")


def generate(policy: Policy, rng: Optional[secrets.SystemRandom] = None) -> str:
    """Generate one password uniformly at random from all passwords the policy allows.

    The first character is drawn from the characters allowed in first position
    and the rest from the full alphabet; candidates that miss a minimum count
    are rejected. This keeps the distribution uniform over valid passwords, so
    the entropy reported by :meth:`Policy.entropy_bits` is exact.
    """
    rng = rng or secrets.SystemRandom()
    classes = policy.classes()
    alphabet = "".join(chars for _, chars, _ in classes)
    first_alphabet = "".join(c for c in alphabet if policy.first_char_filter(c))
    if not first_alphabet:
        raise PolicyError("no character is allowed in the first position")
    if policy.acceptance_rate() < MIN_ACCEPTANCE:
        raise PolicyError("minimum counts are too strict for this length - increase the length or lower the minimums")
    while True:
        pw = rng.choice(first_alphabet) + "".join(rng.choice(alphabet) for _ in range(policy.length - 1))
        if all(sum(ch in chars for ch in pw) >= minimum for _, chars, minimum in classes):
            return pw


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #


def build_rows(
    passwords: Sequence[str],
    labels: Sequence[str],
    policy: Policy,
    assessment: Optional[exposure.Assessment],
    today: Optional[dt.date] = None,
) -> tuple[list[str], list[list[str]]]:
    bits = policy.entropy_bits()
    header = ["Account" if any(labels) else "#", "Password", "Length", "Entropy (bits)"]
    extra: list[str] = []
    if assessment:
        today = today or dt.date.today()
        rotate_by = (today + dt.timedelta(days=assessment.rotation_days)).isoformat()
        meets = "Yes" if bits >= assessment.required_bits and policy.length >= assessment.min_length_floor else "No"
        rate = assessment.offline_guesses_per_second or assessment.online_guesses_per_second
        crack = exposure.human_duration(exposure.average_crack_seconds(bits, rate))
        header += ["Required (bits)", "Meets policy", "Avg crack time", "Generated", "Rotate by"]
        extra = [str(assessment.required_bits), meets, crack, today.isoformat(), rotate_by]
    rows = []
    for i, pw in enumerate(passwords):
        label = labels[i] if i < len(labels) and labels[i] else str(i + 1)
        rows.append([label, pw, str(len(pw)), f"{bits:.1f}", *extra])
    return header, rows


def format_rows(header: list[str], rows: list[list[str]], fmt: str, show_header: bool = True) -> str:
    all_rows = ([header] if show_header else []) + rows
    if fmt == "tsv":
        return "\n".join("\t".join(r) for r in all_rows) + "\n"
    if fmt == "csv":
        buf = io.StringIO()
        csv.writer(buf, lineterminator="\n").writerows(all_rows)
        return buf.getvalue()
    if fmt == "json":
        return json.dumps([dict(zip(header, r)) for r in rows], indent=2) + "\n"
    # Pretty table for reading on screen.
    widths = [max(len(r[i]) for r in all_rows) for i in range(len(header))]
    line = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    out = [line]
    for n, r in enumerate(all_rows):
        out.append("| " + " | ".join(c.ljust(w) for c, w in zip(r, widths)) + " |")
        if show_header and n == 0:
            out.append(line)
    out.append(line)
    return "\n".join(out) + "\n"


def copy_to_clipboard(text: str) -> bool:
    candidates = [
        ["pbcopy"],
        ["wl-copy"],
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
        ["clip.exe"],
        ["clip"],
    ]
    for cmd in candidates:
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, input=text.encode(), check=True)
                return True
            except (OSError, subprocess.CalledProcessError):
                continue
    return False


def write_private(path: str, text: str) -> None:
    """Write a file readable only by the current user."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", newline="") as fh:
        fh.write(text)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _read_labels(args: argparse.Namespace) -> list[str]:
    labels: list[str] = []
    if args.labels:
        labels += [x.strip() for x in args.labels.split(",")]
    if args.labels_file:
        with open(args.labels_file, encoding="utf-8") as fh:
            labels += [line.strip() for line in fh if line.strip()]
    return labels


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cred-passgen",
        description="Generate many passwords at once in a table you can paste into Excel.",
        epilog="Example: cred-passgen -n 10 --exposure internet --privilege critical --hash fast --copy",
    )
    parser.add_argument("-n", "--count", type=int, default=None,
                        help="number of passwords (default: 10, or one per label)")
    parser.add_argument("-l", "--length", type=int, default=None,
                        help=f"password length (default: from the exposure profile, else {DEFAULT_LENGTH})")

    c = parser.add_argument_group("complexity requirements")
    for name in ("upper", "lower", "digits", "symbols"):
        c.add_argument(f"--no-{name}", action="store_true", help=f"do not use {name}")
        c.add_argument(f"--min-{name}", type=int, default=1, metavar="N",
                       help=f"minimum number of {name} (default: 1)")
    c.add_argument("--symbol-set", default=DEFAULT_SYMBOLS, metavar="CHARS",
                   help=f"symbols the target system accepts (default: {DEFAULT_SYMBOLS})")
    c.add_argument("--exclude", default="", metavar="CHARS", help="characters never to use")
    c.add_argument("--no-ambiguous", action="store_true", help=f"exclude look-alike characters ({AMBIGUOUS})")
    c.add_argument("--start-with-letter", action="store_true",
                   help="first character must be a letter (some databases and mainframes require this)")
    c.add_argument("--allow-formula-start", action="store_true",
                   help="allow = + - @ ' as the first character (unsafe when pasted into Excel)")

    o = parser.add_argument_group("output")
    o.add_argument("-f", "--format", choices=["tsv", "table", "csv", "json"], default="tsv",
                   help="tsv pastes cleanly into Excel (default); table is easier to read on screen")
    o.add_argument("--labels", metavar="A,B,C", help="comma-separated account names, one row each")
    o.add_argument("--labels-file", metavar="FILE", help="file with one account name per line")
    o.add_argument("--no-header", action="store_true", help="omit the header row")
    o.add_argument("-o", "--output", metavar="FILE", help="write to FILE (created with 0600 permissions)")
    o.add_argument("--copy", action="store_true", help="copy the table to the clipboard instead of printing it")

    exposure.add_profile_arguments(parser, exposure_default=None)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    policy = Policy(
        upper=not args.no_upper,
        lower=not args.no_lower,
        digits=not args.no_digits,
        symbols=not args.no_symbols,
        min_upper=0 if args.no_upper else args.min_upper,
        min_lower=0 if args.no_lower else args.min_lower,
        min_digits=0 if args.no_digits else args.min_digits,
        min_symbols=0 if args.no_symbols else args.min_symbols,
        symbol_set=args.symbol_set,
        exclude=args.exclude,
        no_ambiguous=args.no_ambiguous,
        start_with_letter=args.start_with_letter,
        excel_safe=not args.allow_formula_start,
    )

    try:
        labels = _read_labels(args)
        count = args.count if args.count is not None else (len(labels) or 10)
        if count < 1:
            raise PolicyError("count must be at least 1")

        assessment = None
        if args.exposure:
            assessment = exposure.assess(exposure.profile_from_args(args))
            recommended = length_for_bits(policy, assessment.required_bits, assessment.min_length_floor)
            policy.length = args.length or recommended
            if args.length and args.length < recommended:
                print(
                    f"warning: length {args.length} is below the recommended {recommended} for this exposure "
                    f"profile and character set ({assessment.required_bits} bits required, minimum length "
                    f"{assessment.min_length_floor} for '{assessment.profile.privilege}' accounts).",
                    file=sys.stderr,
                )
        else:
            policy.length = args.length or DEFAULT_LENGTH

        policy.validate()
        rng = secrets.SystemRandom()
        passwords = [generate(policy, rng) for _ in range(count)]
    except (PolicyError, ValueError, OSError) as exc:
        parser.error(str(exc))

    header, rows = build_rows(passwords, labels, policy, assessment)
    text = format_rows(header, rows, args.format, show_header=not args.no_header)

    if assessment:
        print(
            f"exposure profile: {assessment.required_bits} bits required, length {policy.length}, "
            f"rotate every {assessment.rotation_days} days (run cred-exposure for the full report)",
            file=sys.stderr,
        )

    if args.output:
        write_private(args.output, text)
        print(f"wrote {len(rows)} passwords to {args.output}", file=sys.stderr)
    if args.copy:
        if copy_to_clipboard(text):
            print(f"copied {len(rows)} passwords to the clipboard - paste into cell A1", file=sys.stderr)
        else:
            print("error: no clipboard tool found (pbcopy, wl-copy, xclip, xsel, clip)", file=sys.stderr)
            return 1
    if not args.output and not args.copy:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
