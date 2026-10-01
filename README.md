# cred-verifier

Tools for **custodians of privileged accounts**: the people who hold root,
Administrator, DBA, network-device, service-account and break-glass
credentials, and who rotate them by hand when no PAM product does it for them.

The tools answer the questions a custodian gets asked, or asks themselves,
at rotation time:

* *How long and how complex does this password need to be?*
* *How often should I rotate it?*
* *Can I generate a batch of compliant passwords for all my accounts right now?*

Everything is plain Python 3.9+ with **no third-party dependencies**, so it
runs on hardened jump hosts and PAM workstations where `pip install` from the
internet isn't allowed.

| Tool | What it does |
|------|--------------|
| [`cred-exposure`](#1-exposure-framework-cred-exposure) | Turns a system's exposure profile into a required entropy, a minimum length per character set, and a rotation period. |
| [`cred-passgen`](#2-bulk-password-generator-cred-passgen) | Generates many passwords at once under your complexity rules and outputs a table that pastes straight into Excel. Uses the exposure framework to pick the length and fill in a "rotate by" date. |

---

## Installation

```bash
git clone https://github.com/apjha/cred-verifier.git
cd cred-verifier

# Option A: run in place, nothing to install
python3 -m credverifier.exposure --help
python3 -m credverifier.passgen  --help

# Option B: install the cred-exposure and cred-passgen commands
pip install .
```

---

## 1. Exposure framework (`cred-exposure`)

### Inputs

| Flag | Values | Why it matters |
|------|--------|----------------|
| `--exposure` | `internet`, `partner`, `internal`, `isolated` | How likely the login is to be attacked at all, and how fast it can be hit. |
| `--privilege` | `standard`, `elevated`, `privileged` (default), `critical` | The acceptable chance of compromise, and the minimum length floor (12/14/16/20). |
| `--lockout-threshold N` / `--lockout-minutes M` | e.g. `5` / `30`; `M=0` means an admin has to unlock it | Caps how many online guesses an attacker gets. |
| `--rate-limit PER_MIN` | e.g. `10` | Throttling also caps online guessing. |
| `--mfa` | flag | A guessed password alone no longer gets the attacker in. |
| `--hash` | `plaintext`, `fast`, `iterated`, `slow`, `unknown` (default), `none` | How fast a stolen hash can be cracked offline. This is usually the deciding factor. |
| `--attacker` | `opportunistic`, `organized` (default), `nation-state` | Scales offline cracking power. |
| `--shared-with N` | number of people who know it | Shared secrets leak, so they get rotated more often. |
| `--monitored` | flag | Failed logins are alerted on, so a guessing campaign gets stopped. |
| `--rotation-days D` | e.g. `90` | Use your mandated period instead of the recommended one. The required length is recalculated for it. |

You can also run `cred-exposure -i` to be asked the questions one at a time,
or add `--json` to get machine-readable output.

### Example

```text
$ cred-exposure --exposure internet --privilege critical --hash fast --shared-with 3

Risk score      : 11  (+3 exposure: internet, +3 privilege: critical, +1 hash storage: fast, ...)
Rotation        : every 30 days

Online attack   : 10/s -> needs 47.9 bits
Offline attack  : 2e+12/s -> needs 85.4 bits
Required        : 86 bits of entropy (driven by offline cracking of a stolen hash)
Length floor    : 20 characters for 'critical' accounts

Recommended minimum length (randomly generated):
  digits only (PIN)            26 chars
  lowercase letters            20 chars
  letters + digits             20 chars
  letters + digits + symbols   20 chars
  diceware passphrase           7 words
```

### How it works

A password drawn uniformly at random from `2^H` possibilities survives an
attacker who can make `G` guesses with probability `1 - G/2^H`. To keep the
chance of compromise below `p` during one rotation period:

```
H  >=  log2( G / p )
```

The framework works out `G` for two attacks and uses whichever needs more
entropy:

* **Online guessing** against the live login: the allowed attempt rate
  (limited by lockout or rate limiting) × the rotation period. If failed
  logins are monitored, the window is cut to 7 days. MFA relaxes `p` by 100×.
* **Offline cracking** of a stolen hash: the cracking speed for the hash
  type × the rotation period, since a cracked password stops being useful
  once it is rotated. MFA does **not** help here.

`p` comes from the privilege level (1e-4 for standard down to 1e-7 for
critical). It is then divided by how likely the system is to be targeted at
all (1.0 for internet down to 0.01 for isolated).

**Rotation** comes from an additive risk score made up of exposure,
privilege, hash storage, missing MFA, missing lockout, missing monitoring and
the number of people sharing the credential. The score maps to 30, 60, 90,
180 or 365 days. Credentials stored in plaintext are always capped at
30 days. Because the required length is calculated for the chosen period, a
longer rotation automatically asks for a longer password.

All constants (guess rates, probabilities, tiers) live at the top of
[`credverifier/exposure.py`](credverifier/exposure.py), each with a comment.
They are deliberately round, conservative numbers meant to give the right
order of magnitude. Tune them to your environment and threat model.

> **Rotation and NIST SP 800-63B.** NIST advises *against* forced periodic
> rotation of ordinary user passwords. That advice is about humans choosing
> and memorising their own passwords. Shared, vaulted, privileged and
> break-glass credentials are a different case: rotation limits how long a
> leaked or cracked value stays useful, and it removes access from people who
> no longer need it. Rotate these on a schedule, **and** after every
> break-glass use, a custodian change, or any suspected compromise.

---

## 2. Bulk password generator (`cred-passgen`)

Generates passwords with a cryptographically secure RNG (`secrets`) and
prints them as a table.

### Quick start

```bash
# 10 passwords, 16 chars, all four character classes, tab-separated
cred-passgen

# One row per account, with length, rotation date and crack-time estimate
# picked by the exposure framework, copied straight to the clipboard
cred-passgen --labels "root@db01,sa@sql02,admin@fw01" \
             --exposure internet --privilege critical --hash fast --copy

# Account names from a file, readable table on screen
cred-passgen --labels-file accounts.txt --exposure internal -f table
```

Sample `-f table` output:

```text
+---+----------------------+--------+----------------+-----------------+--------------+----------------+------------+------------+
| # | Password             | Length | Entropy (bits) | Required (bits) | Meets policy | Avg crack time | Generated  | Rotate by  |
+---+----------------------+--------+----------------+-----------------+--------------+----------------+------------+------------+
| 1 | 68k8MHawneb~Zdfs#m*= | 20     | 127.2          | 86              | Yes          | 1.6e+18 years  | 2026-10-01 | 2026-10-31 |
| 2 | 8?j!+R/y]c_v{(P_A2}f | 20     | 127.2          | 86              | Yes          | 1.6e+18 years  | 2026-10-01 | 2026-10-31 |
+---+----------------------+--------+----------------+-----------------+--------------+----------------+------------+------------+
```

### Complexity requirements

| Flag | Meaning |
|------|---------|
| `-l, --length N` | Length. Defaults to the framework's recommendation if `--exposure` is set, otherwise 16. If you choose a shorter length than recommended, you get a warning and `Meets policy = No`. |
| `--no-upper`, `--no-lower`, `--no-digits`, `--no-symbols` | Leave out a character class. |
| `--min-upper N`, `--min-lower N`, `--min-digits N`, `--min-symbols N` | Minimum count per class (default 1 each). |
| `--symbol-set CHARS` | Symbols the target system accepts. Default: `!#$%&()*+,-./:;<=>?@[]^_{\|}~`. Quotes, backslash and backtick are left out because they break shells, scripts and connection strings. |
| `--exclude CHARS` | Characters never to use. |
| `--no-ambiguous` | Leave out look-alike characters (`I l 1 \| O 0 o` and quotes). |
| `--start-with-letter` | First character must be a letter (Oracle, some mainframes and appliances require this). |
| `--allow-formula-start` | Allow `= + - @ '` as the first character. Off by default; see *Excel safety* below. |

Add any of the `cred-exposure` flags (`--exposure`, `--privilege`, `--hash`,
`--lockout-threshold`, ...) to bring in the framework.

### Output

| Flag | Meaning |
|------|---------|
| `-n, --count N` | Number of passwords (default 10, or one per label). |
| `--labels A,B,C` / `--labels-file FILE` | Account names for the first column. |
| `-f, --format` | `tsv` (default, pastes into Excel one value per cell), `table`, `csv`, `json`. |
| `--no-header` | Leave out the header row. |
| `--copy` | Copy to the clipboard instead of printing (uses `pbcopy`, `wl-copy`, `xclip`, `xsel` or `clip`). |
| `-o FILE` | Write to a file created with `0600` permissions. |

### Excel safety

* **Formula injection:** Excel treats a pasted value that starts with
  `=`, `+`, `-` or `@` as a formula, and silently drops a leading `'`. Either
  way the stored password ends up different from the one you set. By default
  passwords never start with those characters.
* **Formatting:** before pasting, set the target column's format to **Text**,
  so that Excel doesn't turn anything into a date or number.
* **Quotes:** if you add `"` to `--symbol-set`, Excel may treat it as a field
  delimiter when pasting TSV. Prefer `-f csv` with *Data → From Text/CSV* in
  that case.

### Entropy is calculated exactly

Minimum-count rules ("at least 2 digits") and first-character rules make the
set of possible passwords smaller, so `length × log2(alphabet)` overstates
the strength. The generator draws uniformly from the set of passwords that
satisfy every rule, using rejection sampling, and
[`credverifier/entropy.py`](credverifier/entropy.py) counts that set exactly
with generating functions. The `Entropy (bits)` column is therefore the true
value, not an estimate.

---

## Handling generated passwords

* Prefer `--copy` or `-o` over printing to the terminal, which leaves
  passwords in scrollback and possibly in session recordings.
* Put the values into your vault or password manager, then **delete the
  spreadsheet and empty the clipboard**. A spreadsheet of live privileged
  passwords is a high-value target.
* `.gitignore` excludes `*.tsv` and `*.csv` so a generated sheet doesn't get
  committed by accident.

---

## Development

```bash
python3 -m unittest discover -s tests -t .
```

Layout:

```
credverifier/
  exposure.py   exposure framework + cred-exposure CLI
  entropy.py    exact entropy counting for policy-constrained passwords
  passgen.py    bulk generator + cred-passgen CLI
tests/          unittest suite (stdlib only)
```

## Roadmap

Ideas for further custodian tools in this repository:

* Verifying that a rotated credential actually works on the target
  (SSH, LDAP/AD bind, database login) without exposing it on the command line
* Checking a candidate password against breach corpora (k-anonymity HIBP lookup)
* A rotation register: tracking last-rotated and next-due dates per account

## License

MIT. See [LICENSE](LICENSE).
