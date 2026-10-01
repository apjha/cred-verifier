"""Password exposure framework.

Turns a description of where a credential lives (how reachable it is, what
protects it from guessing, how its hash is stored, how privileged it is) into:

* the entropy (in bits) a randomly generated password needs,
* the length that entropy implies for common character sets, and
* a rotation period.

The model
---------
An attacker gets a budget of guesses ``G`` over the life of one password
(the rotation period). If the password is drawn uniformly at random from
``2^H`` possibilities, the chance the attacker finds it is ``G / 2^H``. We
want that chance to stay below an acceptable probability ``p``, so

    H >= log2(G / p)

Two attacks are evaluated and the stronger requirement wins:

* **Online** - guessing against the live login. ``G`` is the attempt rate the
  system allows (bounded by lockout / rate limiting) times the time the
  attacker can keep going (the rotation period, or ~7 days if failed logins
  are monitored and would be noticed). MFA makes a correct password guess far
  less useful, so it relaxes ``p``.
* **Offline** - cracking a stolen hash. ``G`` is the cracking speed for the
  hash algorithm times the rotation period (once rotated, the cracked value is
  worthless). MFA does not help here: a cracked password can be replayed
  anywhere it is reused, and lets the attacker wait for an MFA bypass.

``p`` comes from the account's privilege level and is scaled by how likely the
system is to be attacked at all (its exposure).

Every constant below is a deliberately round, conservative, documented
assumption. They are meant to give a custodian an order-of-magnitude feel for
the right answer, not a guarantee. Adjust them for your environment.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import asdict, dataclass, field
from typing import Optional

# --------------------------------------------------------------------------- #
# Assumptions
# --------------------------------------------------------------------------- #

#: exposure -> (likelihood the system is actively attacked,
#:              un-throttled online guesses per second against one account,
#:              risk-score points, description)
EXPOSURE = {
    "internet": (1.0, 10.0, 3, "Reachable from the public internet (SSH/RDP, VPN portal, cloud console, web admin)"),
    "partner": (0.3, 10.0, 2, "DMZ / extranet / reachable by vendors or partners"),
    "internal": (0.1, 100.0, 1, "Corporate network only (attacker needs a foothold first)"),
    "isolated": (0.01, 1.0, 0, "Segmented or air-gapped; console, jump host or PAM session only"),
}

#: privilege -> (acceptable compromise probability per rotation period,
#:               minimum length floor, risk-score points, description)
PRIVILEGE = {
    "standard": (1e-4, 12, 0, "Ordinary user or low-impact application account"),
    "elevated": (1e-5, 14, 1, "Local admin, application admin, sensitive data access"),
    "privileged": (1e-6, 16, 2, "Server root/Administrator, DBA, network device admin, service accounts with broad rights"),
    "critical": (1e-7, 20, 3, "Domain/Enterprise admin, cloud root, break-glass, PAM/vault master, HSM"),
}

#: hash storage -> (offline guesses per second for a ~8 high-end GPU rig,
#:                  risk-score points, description)
#: ``None`` rate means "offline cracking is not the relevant threat".
HASH_STORAGE = {
    "plaintext": (None, 2, "Stored in clear text or reversibly encrypted (config files, scripts, LDAP reversible)"),
    "fast": (2e12, 1, "Fast/unsalted hashes: NTLM, MD5, SHA-1, single-round SHA-2, many network devices"),
    "iterated": (3e7, 0, "Salted & iterated: sha512crypt, PBKDF2 (<600k iterations), Kerberos AES keys"),
    "slow": (1e6, 0, "Memory/CPU-hard: bcrypt (cost>=10), scrypt, Argon2, PBKDF2 (>=600k iterations)"),
    "unknown": (2e12, 1, "Not known - assumed to be fast"),
    "none": (None, 0, "No hash an attacker could realistically obtain (e.g. verified only inside an HSM)"),
}

#: attacker -> (multiplier on offline cracking speed, description)
ATTACKER = {
    "opportunistic": (0.1, "Single GPU, commodity tooling"),
    "organized": (1.0, "Criminal group / ransomware crew with a GPU rig or rented cloud GPUs"),
    "nation-state": (100.0, "Large dedicated cracking clusters"),
}

#: How MFA relaxes the online target: a guessed password alone is not enough.
MFA_ONLINE_FACTOR = 100.0
#: If failed logins are monitored and alerted on, assume a guessing campaign is
#: noticed and stopped within this many days.
MONITORED_WINDOW_DAYS = 7
#: Lockout that requires an admin to unlock: assume the account is unlocked
#: (by help desk or the attacker waiting) once per day.
ADMIN_UNLOCK_SECONDS = 86400
#: Never let p exceed this - beyond it the maths stops meaning anything.
MAX_PROBABILITY = 0.5

#: (minimum risk score, rotation days) - first match wins.
ROTATION_TIERS = [(10, 30), (7, 60), (5, 90), (3, 180), (0, 365)]

#: Reference alphabets for the recommendation table.
CHARSETS = [
    ("digits only (PIN)", 10),
    ("lowercase letters", 26),
    ("letters + digits", 62),
    ("letters + digits + symbols", 94),
]
DICEWARE_WORDS = 7776

SECONDS_PER_DAY = 86400


# --------------------------------------------------------------------------- #
# Profile and assessment
# --------------------------------------------------------------------------- #


@dataclass
class Profile:
    """Everything the framework needs to know about one credential."""

    exposure: str = "internal"
    privilege: str = "privileged"
    lockout_threshold: int = 0  # 0 = no lockout
    lockout_minutes: int = 30  # 0 = stays locked until an admin unlocks it
    rate_limit_per_minute: float = 0.0  # 0 = no rate limiting
    mfa: bool = False
    hash_storage: str = "unknown"
    attacker: str = "organized"
    shared_with: int = 1  # number of people who know the password
    monitored: bool = False  # failed logins alerted on
    rotation_days: Optional[int] = None  # override the recommended period

    def validate(self) -> None:
        for name, table in (
            ("exposure", EXPOSURE),
            ("privilege", PRIVILEGE),
            ("hash_storage", HASH_STORAGE),
            ("attacker", ATTACKER),
        ):
            if getattr(self, name) not in table:
                raise ValueError(f"{name} must be one of: {', '.join(table)}")
        if self.lockout_threshold < 0 or self.lockout_minutes < 0:
            raise ValueError("lockout values cannot be negative")
        if self.rate_limit_per_minute < 0:
            raise ValueError("rate limit cannot be negative")
        if self.shared_with < 1:
            raise ValueError("shared_with must be at least 1")
        if self.rotation_days is not None and self.rotation_days < 1:
            raise ValueError("rotation_days must be at least 1")


@dataclass
class Assessment:
    profile: Profile
    risk_score: int
    risk_factors: list[str]
    rotation_days: int
    recommended_rotation_days: int
    online_guesses_per_second: float
    online_bits: float
    offline_guesses_per_second: Optional[float]
    offline_bits: float
    required_bits: int
    min_length_floor: int
    lengths: dict[str, int]
    passphrase_words: int
    notes: list[str] = field(default_factory=list)

    @property
    def driver(self) -> str:
        if self.offline_bits >= self.online_bits:
            return "offline cracking of a stolen hash"
        return "online guessing against the login"

    def length_for_alphabet(self, alphabet_size: int) -> int:
        return length_for(self.required_bits, alphabet_size, self.min_length_floor)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["driver"] = self.driver
        return d


def length_for(bits: float, alphabet_size: int, floor: int = 0) -> int:
    """Shortest length of a uniformly random string reaching ``bits``."""
    if alphabet_size < 2:
        raise ValueError("alphabet must contain at least 2 characters")
    return max(math.ceil(bits / math.log2(alphabet_size)), floor)


def online_rate(profile: Profile) -> float:
    """Sustained online guesses per second against a single account."""
    _, rate, _, _ = EXPOSURE[profile.exposure]
    if profile.lockout_threshold > 0:
        window = profile.lockout_minutes * 60 if profile.lockout_minutes > 0 else ADMIN_UNLOCK_SECONDS
        rate = min(rate, profile.lockout_threshold / window)
    if profile.rate_limit_per_minute > 0:
        rate = min(rate, profile.rate_limit_per_minute / 60)
    return rate


def offline_rate(profile: Profile) -> Optional[float]:
    base, _, _ = HASH_STORAGE[profile.hash_storage]
    if base is None:
        return None
    return base * ATTACKER[profile.attacker][0]


def risk_score(profile: Profile) -> tuple[int, list[str]]:
    """Additive score that drives the rotation period."""
    factors: list[tuple[int, str]] = [
        (EXPOSURE[profile.exposure][2], f"exposure: {profile.exposure}"),
        (PRIVILEGE[profile.privilege][2], f"privilege: {profile.privilege}"),
        (HASH_STORAGE[profile.hash_storage][1], f"hash storage: {profile.hash_storage}"),
        (0 if profile.mfa else 1, "no MFA"),
        (0 if (profile.lockout_threshold or profile.rate_limit_per_minute) else 1, "no lockout / rate limit"),
        (0 if profile.monitored else 1, "failed logins not monitored"),
    ]
    if profile.shared_with > 5:
        factors.append((2, f"shared by {profile.shared_with} people"))
    elif profile.shared_with > 1:
        factors.append((1, f"shared by {profile.shared_with} people"))
    score = sum(points for points, _ in factors)
    return score, [f"+{points} {label}" for points, label in factors if points]


def recommended_rotation(profile: Profile, score: int) -> int:
    days = next(d for threshold, d in ROTATION_TIERS if score >= threshold)
    if profile.hash_storage == "plaintext":
        days = min(days, 30)
    return days


def _bits(guesses: float, probability: float) -> float:
    if guesses <= 0:
        return 0.0
    return max(math.log2(guesses / probability), 0.0)


def assess(profile: Profile) -> Assessment:
    """Run the framework for one credential profile."""
    profile.validate()
    score, factors = risk_score(profile)
    rec_days = recommended_rotation(profile, score)
    days = profile.rotation_days or rec_days
    period = days * SECONDS_PER_DAY

    likelihood = EXPOSURE[profile.exposure][0]
    p_base, floor, _, _ = PRIVILEGE[profile.privilege]
    p = min(p_base / likelihood, MAX_PROBABILITY)

    on_rate = online_rate(profile)
    on_window = min(period, MONITORED_WINDOW_DAYS * SECONDS_PER_DAY) if profile.monitored else period
    p_online = min(p * (MFA_ONLINE_FACTOR if profile.mfa else 1.0), MAX_PROBABILITY)
    on_bits = _bits(on_rate * on_window, p_online)

    off_rate = offline_rate(profile)
    off_bits = _bits(off_rate * period, p) if off_rate else 0.0

    required = math.ceil(max(on_bits, off_bits))
    lengths = {name: length_for(required, size, floor) for name, size in CHARSETS}
    words = max(math.ceil(required / math.log2(DICEWARE_WORDS)), 4)

    notes = []
    if profile.hash_storage == "plaintext":
        notes.append(
            "The password is stored in clear text or reversibly: anyone who reads that store has it, "
            "whatever its length. Rotation (ideally after every use) and moving it into a vault are "
            "the controls that matter."
        )
    if profile.hash_storage in ("fast", "unknown"):
        notes.append(
            "Fast or unknown hashing makes offline cracking the dominant threat. Moving to a slow hash "
            "(bcrypt/scrypt/Argon2) or enforcing MFA on the account shortens the required length."
        )
    if profile.exposure == "internet" and not profile.mfa:
        notes.append("An internet-reachable privileged login without MFA is a finding in its own right.")
    if profile.shared_with > 1:
        notes.append(
            "Shared credentials: rotate whenever someone who knows it changes role or leaves, and "
            "prefer per-person accounts or PAM check-out with rotate-on-check-in."
        )
    if profile.privilege == "critical":
        notes.append("Break-glass / critical credentials should also be rotated after every use.")
    if profile.rotation_days and profile.rotation_days > rec_days:
        notes.append(
            f"Rotation period {profile.rotation_days}d is longer than the recommended {rec_days}d; "
            "the required length was increased to compensate for the longer attack window."
        )
    notes.append("Always rotate immediately on suspected compromise, custodian change or vendor access ending.")

    return Assessment(
        profile=profile,
        risk_score=score,
        risk_factors=factors,
        rotation_days=days,
        recommended_rotation_days=rec_days,
        online_guesses_per_second=on_rate,
        online_bits=round(on_bits, 1),
        offline_guesses_per_second=off_rate,
        offline_bits=round(off_bits, 1),
        required_bits=required,
        min_length_floor=floor,
        lengths=lengths,
        passphrase_words=words,
        notes=notes,
    )


# --------------------------------------------------------------------------- #
# Crack-time estimates
# --------------------------------------------------------------------------- #


def average_crack_seconds(bits: float, guesses_per_second: Optional[float]) -> Optional[float]:
    """Average time to find a random password of ``bits`` entropy (half the space)."""
    if not guesses_per_second:
        return None
    return 2 ** (bits - 1) / guesses_per_second


def human_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "n/a"
    units = [
        ("years", 365 * SECONDS_PER_DAY),
        ("days", SECONDS_PER_DAY),
        ("hours", 3600),
        ("minutes", 60),
        ("seconds", 1),
    ]
    if seconds < 1:
        return "< 1 second"
    years = seconds / units[0][1]
    if years >= 1e6:
        return f"{years:.1e} years"
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            return f"{value:,.0f} {name}" if value >= 10 else f"{value:.1f} {name}"
    return f"{seconds:.0f} seconds"


def _rate(rate: Optional[float]) -> str:
    if rate is None:
        return "n/a"
    if rate >= 1:
        return f"{rate:.3g}/s"
    return f"{rate * 3600:.3g}/hour"


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def render(a: Assessment) -> str:
    p = a.profile
    lockout = "none"
    if p.lockout_threshold:
        lockout = f"{p.lockout_threshold} attempts, " + (
            f"{p.lockout_minutes} min" if p.lockout_minutes else "admin unlock"
        )
    lines = [
        "Credential exposure assessment",
        "=" * 30,
        f"Exposure        : {p.exposure} - {EXPOSURE[p.exposure][3]}",
        f"Privilege       : {p.privilege} - {PRIVILEGE[p.privilege][3]}",
        f"Lockout         : {lockout}"
        + (f"; rate limit {p.rate_limit_per_minute:g}/min" if p.rate_limit_per_minute else ""),
        f"MFA             : {'yes' if p.mfa else 'no'}",
        f"Hash storage    : {p.hash_storage} - {HASH_STORAGE[p.hash_storage][2]}",
        f"Attacker        : {p.attacker} - {ATTACKER[p.attacker][1]}",
        f"Shared with     : {p.shared_with} {'person' if p.shared_with == 1 else 'people'}",
        f"Monitored       : {'yes' if p.monitored else 'no'}",
        "",
        f"Risk score      : {a.risk_score}  ({', '.join(a.risk_factors) or 'no risk factors'})",
        f"Rotation        : every {a.rotation_days} days"
        + ("" if a.rotation_days == a.recommended_rotation_days else f" (recommended: {a.recommended_rotation_days})"),
        "",
        f"Online attack   : {_rate(a.online_guesses_per_second)} -> needs {a.online_bits} bits",
        f"Offline attack  : {_rate(a.offline_guesses_per_second)} -> needs {a.offline_bits} bits",
        f"Required        : {a.required_bits} bits of entropy (driven by {a.driver})",
        f"Length floor    : {a.min_length_floor} characters for '{p.privilege}' accounts",
        "",
        "Recommended minimum length (randomly generated):",
    ]
    width = max(len(name) for name in a.lengths)
    for name, size in CHARSETS:
        length = a.lengths[name]
        bits = length * math.log2(size)
        crack = human_duration(average_crack_seconds(bits, a.offline_guesses_per_second or a.online_guesses_per_second))
        lines.append(f"  {name:<{width}}  {length:>3} chars   (avg crack time {crack})")
    lines.append(f"  {'diceware passphrase':<{width}}  {a.passphrase_words:>3} words")
    lines.append("")
    lines.append("Notes:")
    lines.extend(f"  - {n}" for n in a.notes)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def add_profile_arguments(parser: argparse.ArgumentParser, exposure_default: Optional[str] = "internal") -> None:
    """Add the framework's inputs to an argparse parser (shared with passgen)."""
    g = parser.add_argument_group("exposure profile")
    g.add_argument("--exposure", choices=EXPOSURE, default=exposure_default,
                   help="how reachable the system's login is")
    g.add_argument("--privilege", choices=PRIVILEGE, default="privileged",
                   help="impact if the account is compromised (default: privileged)")
    g.add_argument("--lockout-threshold", type=int, default=0, metavar="N",
                   help="failed attempts before lockout (0 = no lockout)")
    g.add_argument("--lockout-minutes", type=int, default=30, metavar="M",
                   help="lockout duration in minutes (0 = until an admin unlocks; default: 30)")
    g.add_argument("--rate-limit", type=float, default=0.0, metavar="PER_MIN", dest="rate_limit_per_minute",
                   help="max login attempts per minute enforced by the system (0 = none)")
    g.add_argument("--mfa", action="store_true", help="the account requires MFA to log in")
    g.add_argument("--hash", choices=HASH_STORAGE, default="unknown", dest="hash_storage",
                   help="how the system stores the password (default: unknown, treated as fast)")
    g.add_argument("--attacker", choices=ATTACKER, default="organized",
                   help="capability of the attacker you plan for (default: organized)")
    g.add_argument("--shared-with", type=int, default=1, metavar="N",
                   help="number of people who know the password (default: 1)")
    g.add_argument("--monitored", action="store_true",
                   help="failed logins on this account raise alerts that someone acts on")
    g.add_argument("--rotation-days", type=int, default=None, metavar="DAYS",
                   help="use this rotation period instead of the recommended one")


def profile_from_args(args: argparse.Namespace) -> Profile:
    return Profile(
        exposure=args.exposure,
        privilege=args.privilege,
        lockout_threshold=args.lockout_threshold,
        lockout_minutes=args.lockout_minutes,
        rate_limit_per_minute=args.rate_limit_per_minute,
        mfa=args.mfa,
        hash_storage=args.hash_storage,
        attacker=args.attacker,
        shared_with=args.shared_with,
        monitored=args.monitored,
        rotation_days=args.rotation_days,
    )


def _ask(question: str, default, choices: Optional[dict] = None, cast=str):
    if choices:
        print(question)
        keys = list(choices)
        for i, key in enumerate(keys, 1):
            desc = choices[key][-1] if isinstance(choices[key], tuple) else ""
            print(f"  {i}) {key:<14} {desc}")
    while True:
        raw = input(f"> [{default}] ").strip()
        if not raw:
            return default
        if choices:
            if raw.isdigit() and 1 <= int(raw) <= len(choices):
                return list(choices)[int(raw) - 1]
            if raw in choices:
                return raw
            print("  please pick one of the options")
            continue
        if cast is bool:
            if raw.lower() in ("y", "yes"):
                return True
            if raw.lower() in ("n", "no"):
                return False
            print("  please answer y or n")
            continue
        try:
            return cast(raw)
        except ValueError:
            print("  invalid value")


def interactive_profile() -> Profile:
    p = Profile()
    p.exposure = _ask("Where can the login for this account be reached from?", p.exposure, EXPOSURE)
    p.privilege = _ask("How privileged is the account?", p.privilege, PRIVILEGE)
    p.lockout_threshold = _ask("Failed attempts before lockout (0 = never locks):", 0, cast=int)
    if p.lockout_threshold:
        p.lockout_minutes = _ask("Lockout duration in minutes (0 = admin must unlock):", 30, cast=int)
    p.rate_limit_per_minute = _ask("Login attempts allowed per minute (0 = unlimited / unknown):", 0.0, cast=float)
    p.mfa = _ask("Does the login require MFA? (y/n)", False, cast=bool)
    p.hash_storage = _ask("How does the system store the password?", p.hash_storage, HASH_STORAGE)
    p.attacker = _ask("Which attacker are you planning for?", p.attacker, ATTACKER)
    p.shared_with = _ask("How many people know the password?", 1, cast=int)
    p.monitored = _ask("Are failed logins alerted on and acted upon? (y/n)", False, cast=bool)
    print()
    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cred-exposure",
        description="Recommend password length, complexity and rotation for a credential based on system exposure.",
    )
    parser.add_argument("-i", "--interactive", action="store_true", help="answer questions instead of using flags")
    parser.add_argument("--json", action="store_true", help="print the assessment as JSON")
    add_profile_arguments(parser)
    args = parser.parse_args(argv)

    try:
        profile = interactive_profile() if args.interactive else profile_from_args(args)
        if args.interactive and args.rotation_days:
            profile.rotation_days = args.rotation_days
        result = assess(profile)
    except ValueError as exc:
        parser.error(str(exc))
    except (KeyboardInterrupt, EOFError):
        print(file=sys.stderr)
        return 130

    print(json.dumps(result.to_dict(), indent=2) if args.json else render(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
