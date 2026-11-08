# pqscan

[![CI](https://github.com/HarenaFiantso/pqscan/actions/workflows/ci.yml/badge.svg)](https://github.com/HarenaFiantso/pqscan/actions/workflows/ci.yml)

pqscan is a command-line tool, written in C, that finds cryptography quantum computers
will break across C/C++ source, configuration files, certificates and ELF binaries.

![pqscan reporting RSA and DSA with their key sizes in a sample file, then nothing in a clean directory](assets/demo.gif)

A large enough quantum computer running Shor's algorithm would break RSA, ECDSA, EdDSA,
ECDH, DH and DSA. pqscan exists because you can't migrate what you can't find: it shows
where that cryptography is and how urgently each use needs to be replaced.

> [!IMPORTANT]
> NIST plans to deprecate these algorithms after 2030 and disallow them after 2035.

The [website](https://harenafiantso.github.io/pqscan/) is a guided tour of everything below.

## Status

> [!WARNING]
> Early development. pqscan scans C/C++ source for the OpenSSL identifiers in its rules,
> through the syntax tree, and follows constants inside a file to find key sizes and algorithm
> names. It also reads the TLS and SSH settings of OpenSSL, nginx, Apache and OpenSSH, and
> certificates and keys in PEM or DER, and the symbol tables of 64-bit ELF binaries. A value
> it can't prove shows as `unknown`. Each finding gets a priority from the NIST IR 8547 dates and
> Mosca's theorem, and reports come as text, JSON, a CycloneDX CBOM or SARIF. A baseline of
> accepted findings and a GitHub Action let CI fail only on new ones.

## Build and test

You need CMake 3.20 or newer, a C11 compiler (GCC or Clang) and OpenSSL 3.0 or newer with its
headers, on Linux or macOS: `brew install openssl@3` or `apt-get install libssl-dev`. On macOS
CMake finds Homebrew's OpenSSL by itself. Elsewhere, set `OPENSSL_ROOT_DIR` if it's not in a
standard place.

> [!TIP]
> If you have Docker, `docker compose run --rm dev` opens a Linux shell with everything
> installed.

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
./build/debug/pqscan --help
```

The `debug` preset builds with ASan and UBSan, `release` is optimized, `valgrind` also
runs each test under a memory checker, and `fuzz` builds the libFuzzer targets. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
full developer setup.

## Usage

```sh
pqscan [OPTIONS] PATH...
```

Each `PATH` is a file or a directory. Directories are walked recursively and symlinks are
never followed. pqscan reads four kinds of files, and skips every other file. The first three
are chosen by name. Binaries rarely have an extension, so ELF files are recognized by their
first four bytes instead, whatever their name:

| Kind | Files |
| --- | --- |
| C and C++ source | `.c`, `.h`, `.cpp`, `.hpp`, `.cc`, `.cxx`, `.C`, `.hh`, `.hxx`, `.ipp`, `.inl` and `.tcc` |
| Configuration | `.conf`, `.cnf`, `sshd_config`, `ssh_config`, `.htaccess`, and any file in a `sites-available` or `sites-enabled` directory |
| Certificates and keys | `.pem`, `.crt`, `.cer`, `.der`, `.key` and `.csr` |
| ELF binaries | 64-bit executables, shared libraries and object files |

Each finding is one line, most urgent first, and a last line counts them. A clean scan prints
nothing:

```text
etc/ssh/sshd_config:4: SHA-1 (CLASSICALLY_WEAK, priority 100)
src/hash.c:12: MD5 (CLASSICALLY_WEAK, priority 100)
src/keys.c:51: RSA-1024 (CLASSICALLY_WEAK, priority 100)
bin/server: ECDSA (QUANTUM_VULNERABLE, priority 51)
src/keys.c:42: RSA-2048 (QUANTUM_VULNERABLE, priority 51)
src/keys.c:57: RSA-unknown (QUANTUM_VULNERABLE, priority 51)
tls/ca.der: EC-256 (QUANTUM_VULNERABLE, priority 51, expires 2035-01-01)
tls/server.pem:1: RSA-2048 (QUANTUM_VULNERABLE, priority 51, expires 2031-05-01)
8 findings: 3 CLASSICALLY_WEAK, 5 QUANTUM_VULNERABLE
```

File names are untrusted input, so control characters, bidirectional marks and invalid UTF-8
in them print as `\xNN`, and a backslash prints doubled.

The number is the key size. `unknown` means the algorithm has one, but pqscan can't prove its
value. RSA, DSA and DH keys under 2048 bits are `CLASSICALLY_WEAK`, because they are already
unsafe today. An `unknown` size keeps the algorithm's usual level. The priority says how soon to
migrate, as [Priorities](#priorities) explains.

### Source

pqscan parses each file with [Tree-sitter](https://tree-sitter.github.io), so broken code
is still scanned:

* **Reported:** calls and other uses of known identifiers, including in macro bodies and in
  every branch of `#ifdef`, plus algorithm names passed to known calls, such as `"RSA"` in
  `EVP_PKEY_CTX_new_from_name`.
* **Reported only when called:** `MD5` and `SHA1`, since those names are also common enum
  values and variables.
* **Not reported:** comments, other strings, declarations such as prototypes, struct fields,
  C++ methods, and code under a literal `#if 0`.

pqscan follows constants inside one file, so all of these report `RSA-4096`:

```c
#define KEY_BITS 4096
static const int DOUBLE_BITS = 2048 * 2;

RSA_generate_key_ex(r, KEY_BITS, NULL, NULL);
RSA_generate_key_ex(r, DOUBLE_BITS, NULL, NULL);
int bits = KEY_BITS;
RSA_generate_key_ex(r, bits, NULL, NULL);
RSA_generate_key_ex(r, 1 << 12, NULL, NULL);
```

It follows locals in order, `#define`s, `const` and `constexpr` globals, strings, and `+`, `-`,
`*` and `<<`. It never guesses, so these stay `unknown`:

* Anything from another file, a parameter, or a global that isn't constant.
* A variable written in a branch, from that write on, or in a loop, from the start of the loop.
* A variable changed by `+=` or `++`, or whose address is taken. In C++, also one passed to a
  call or bound to a reference, since the call could change it.
* A macro with parameters, named by `#undef`, defined twice differently, or defined inside
  `#if` or `#ifdef`, other than a header's include guard. That includes `#ifndef BITS` defaults,
  which the build can override.

Enum constants aren't followed yet, so they also stay `unknown`.

### Configuration

pqscan reads the settings that list algorithms, and looks each name up in its rules:

| Software | Settings |
| --- | --- |
| OpenSSL (`openssl.cnf`) | `CipherString`, `Ciphersuites`, `Groups`, `Curves`, `SignatureAlgorithms`, `ClientSignatureAlgorithms`, and `default_bits` and `default_md` for `openssl req` |
| nginx | `ssl_ciphers`, `ssl_ecdh_curve`, `proxy_ssl_ciphers`, `grpc_ssl_ciphers`, and the OpenSSL settings above through `ssl_conf_command` and its `proxy_` and `grpc_` forms |
| Apache | `SSLCipherSuite`, `SSLProxyCipherSuite`, and the OpenSSL settings above through `SSLOpenSSLConfCmd` |
| OpenSSH | `KexAlgorithms`, `HostKeyAlgorithms`, `PubkeyAcceptedAlgorithms`, `HostbasedAcceptedAlgorithms`, `CASignatureAlgorithms`, `Ciphers` and `MACs`, and their older `KeyTypes` names |

Comments, quotes, `key = value`, statements that span lines and backslash continuations are
all understood, and setting names ignore case. In OpenSSL lists, a full cipher name is split
into its parts, so `ECDHE-RSA-AES128-GCM-SHA256` reports ECDH, RSA and AES-128. A name that a
setting takes away is not reported: `!RSA` and `-SHA1` in OpenSSL lists, and a whole OpenSSH
list that starts with `-`. Hybrid post-quantum groups such as `X25519MLKEM768` and
`mlkem768x25519-sha256` have no rule, so they report nothing, but a classical group listed next
to them still does.

Where one name stands for two weaknesses, pqscan reports the more severe. `ssh-rsa` signs
with SHA-1, so it is `SHA-1 (CLASSICALLY_WEAK)` rather than RSA, while `rsa-sha2-256` is RSA.

> [!NOTE]
> pqscan reports only the names a file writes out. Aliases such as `DEFAULT`, `HIGH` or `ALL`
> are not expanded, because what they mean depends on the OpenSSL build that reads them. For
> the same reason, a TLS 1.2 cipher with no key exchange in its name, such as `AES128-SHA`,
> reports AES-128 and SHA-1 but not the RSA key exchange it implies.

### Certificates and keys

pqscan decodes certificates, certificate requests, public and private keys, and DH, DSA and
EC parameters with OpenSSL's libcrypto, in PEM or DER. A PEM file can hold any number of
blocks, such as a bundle or a certificate with its key, and each finding names the line of its
`-----BEGIN` marker. A DER file has no lines, so its findings name only the file.

* **A certificate** reports its key, with its size and its expiry, and the algorithm that signed
  it. A key used only to sign is a `signature`, and so on, from the certificate's key usage.
  A signature made with SHA-1 or MD5 also reports that digest.
* **A key** reports its algorithm and size. An encrypted key in OpenSSL's traditional form still
  names its algorithm, with an `unknown` size. An encrypted PKCS#8 key hides its algorithm, so
  the file is not analyzed. pqscan never asks for a passphrase.

OpenSSL starts without reading `OPENSSL_CONF`, so a scan never depends on its environment.

### ELF binaries

pqscan reads the symbol table and the dynamic symbol table of 64-bit ELF files, in either
byte order and for any processor, with its own reader. It never runs or loads what it scans,
and checks every offset a file states before reading through it, so a hostile binary can't
make it read out of bounds.

Each function symbol is looked up in the `function` rules, whether the file defines it or
needs it from a library, so `RSA_sign` imported from `libcrypto.so.3` and a copy of OpenSSL
linked into the binary both count. An object file names what it calls with untyped symbols,
and those count too. Data symbols don't. A binary has no lines, so findings name only the
file, and each rule gives at most one finding per file. A binary doesn't keep the arguments of
a call either, so `RSA_generate_key_ex` reports `RSA-unknown`.

> [!NOTE]
> pqscan sees only what the symbols show. A stripped, statically linked executable keeps no
> symbol table, so its file is not analyzed. Algorithms chosen by name at run time, as with
> `EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)`, leave only the generic function in the
> symbols, and no rule names it. 32-bit ELF files, and `.a` archives of object files, are not
> read yet.

| Option | Meaning |
| --- | --- |
| `-i`, `--ignore PATTERN` | Skip paths matching a glob, tried on the file name, the path, and the path relative to `PATH`. Repeatable. `.git` is always skipped. |
| `-r`, `--rules FILE` | Use the rules in this JSON file instead of the built-in ones. |
| `--project FILE` | Read how long data must stay secret from this [project file](#the-project-file). The default is `.pqscan.json` in the current directory, if there is one. |
| `--as-of YEAR` | Score priorities as if it were this year, from 1970 to 9999. The default is the current year, in UTC. |
| `-f`, `--format FORMAT` | Write the report as `text` (the default), `json`, `cbom` or `sarif`. |
| `--fail-on LEVEL` | The lowest risk level that makes pqscan exit 1: `OK`, `REVIEW`, `QUANTUM_VULNERABLE` or `CLASSICALLY_WEAK`. The default is `REVIEW`. It changes only the exit code: every finding is still reported. |
| `--diff FILE` | Report only the findings this [baseline](#baselines-and-ci) does not accept. |
| `--write-baseline FILE` | Write a baseline that accepts every finding to this file, and report as usual. |
| `--max-time SECS` | Start on no new file after this long. The default is 3600. Files left over are skipped, so the scan is incomplete. |
| `-h`, `--help` | Show the help and exit. |
| `-V`, `--version` | Show the version and exit. |

> [!NOTE]
> Paths that can't be read are skipped with a warning on stderr, as are files over 64 MiB,
> source and configuration files that contain a NUL byte, source files that take more than 30
> seconds to parse, encrypted PKCS#8 keys, certificate or key files that can't be decoded, and
> ELF files that are 32-bit, damaged, or have no symbol table. A scan that skips any of them is
> incomplete, and can't exit 0. A PEM file with one bad block, or an ELF file with one damaged
> symbol table, still reports the rest. If a file is skipped on purpose, leave it out with
> `--ignore`. Symlinks inside a directory are skipped by design and don't count, but a
> `PATH` that is one does.

| Exit code | Meaning |
| --- | --- |
| 0 | No findings at or above `--fail-on`, and everything in scope was analyzed |
| 1 | Findings at or above `--fail-on`, even if the scan was incomplete. With `--diff`, only new findings count, and with `--write-baseline`, none do |
| 2 | Usage error, such as a path that doesn't exist or a rule, project or baseline file that isn't valid |
| 3 | Internal error |
| 4 | No findings at or above `--fail-on`, but something in scope could not be analyzed |

> [!CAUTION]
> Exit code 0 doesn't prove the code is free of vulnerable cryptography. pqscan only
> recognizes the names in its rules, in the kinds of files listed above.

## Priorities

Every finding gets a priority from 0 to 100, and reports list the most urgent first. Findings
with the same priority go by path, then line.

| Risk level | Priority |
| --- | --- |
| `CLASSICALLY_WEAK` | 100. It is broken today, so nothing can be more urgent. |
| `QUANTUM_VULNERABLE` | From 50 to 99, from the timeline below. |
| `REVIEW` | 10. Grover's algorithm weakens it, but there is no deadline. |
| `OK` | 0. |

For a quantum-vulnerable finding, pqscan applies Mosca's theorem. If data must stay secret for
X years, migrating takes Y years, and a quantum computer arrives in Q years, then the data is
exposed when X + Y > Q, because what an attacker records today can be decrypted later. The
priority is the sum of:

* 50.
* 10 if NIST IR 8547 deprecates the algorithm in the year the migration would end, which is any
  year after 2030, or 20 if it disallows it, after 2035.
* 10 + X + Y − Q, kept between 0 and 29. It is over 10 exactly when the data is exposed, and
  every year of exposure adds a point.

Q counts the years from `--as-of`, the current year by default, to the quantum year, which is
2035 unless the project file says otherwise. 2035 is when IR 8547 disallows these algorithms:
a planning date, not a forecast.

Without a project file, X and Y are 0, so the priority comes from the dates alone: 51 in 2026,
and more each year after. A component whose data must stay secret for 25 years and takes 7
years to migrate scores 89 in 2026: 50, plus 10 because 2033 is after 2030, plus 29, the cap of
10 + 25 + 7 − 9.

### The project file

A project file says how long the data behind each part of the code must stay secret:

```json
{
  "schema_version": 1,
  "quantum_year": 2035,
  "secrecy_years": 0,
  "migration_years": 3,
  "components": [
    {"name": "payments", "paths": ["src/payments/*", "*.pem"], "secrecy_years": 25, "migration_years": 7},
    {"name": "telemetry", "paths": ["src/telemetry/*"], "secrecy_years": 1}
  ]
}
```

| Field | Meaning |
| --- | --- |
| `schema_version` | Always 1. |
| `quantum_year` | Optional. The year a quantum computer is assumed to break RSA and ECC. The default is 2035. |
| `secrecy_years` | Optional. X, in years, for a path no component claims. The default is 0. |
| `migration_years` | Optional. Y, in years, for a path no component claims. The default is 0. |
| `components` | Optional. Parts of the project with their own years. |
| `components[].name` | A name, shown in reports. |
| `components[].paths` | Globs, as for `--ignore`, tried on the file name and on the path as the report prints it, without a leading `./`. A `*` also matches `/`. |
| `components[].secrecy_years`, `components[].migration_years` | Optional. X and Y for these paths. The defaults are the top-level ones. |

The first component with a matching pattern wins, so put a narrow component before a broad one.
Years go from 0 to 1000. Patterns match the paths a report prints, so run pqscan from the
directory the patterns start at, usually the root of the project, where `.pqscan.json` is read
from. pqscan refuses the whole file on any mistake, such as an unknown field, and a file that
exists but can't be used is a usage error rather than a reason to score without it.

> [!NOTE]
> A project file changes only priorities and their order. It never hides a finding or changes
> the exit code, so reading one from the tree being scanned is safe.

## Reports

`--format` picks what goes to stdout. Warnings always go to stderr, so a report can be
redirected to a file as it is. The same files, rules, project file and `--as-of` year give the
same bytes: reports hold no timestamp and no random identifier.

| Format | What it's for |
| --- | --- |
| `text` | Reading in a terminal. |
| `json` | Scripts. |
| `cbom` | An inventory of the cryptography in use, as a CycloneDX 1.6 CBOM. |
| `sarif` | Code scanning services, as SARIF 2.1.0. |

Every format says what a scan left out, so a partial report can't pass for a whole one.

| Format | Where to look |
| --- | --- |
| `json` | `complete` and `unanalyzed` |
| `cbom` | The `pqscan:scan-complete` and `pqscan:unanalyzed` properties in `metadata` |
| `sarif` | `executionSuccessful` and `toolExecutionNotifications` in `invocations` |
| `text` | The warnings on stderr |

In `json`, one finding looks like this. `key_size` is a number, `"unknown"` when pqscan can't
prove it, or `null` when the algorithm has no key size. `symbol` is the rule pattern that
matched, or for a certificate's signature, the signature algorithm, such as
`sha256WithRSAEncryption`. `line` is `null` for a finding about a whole file, such as a DER
certificate. `expires` is when the certificate stops being valid, in UTC, and `null` for
anything that isn't a certificate. `priority` has the score and the component, `null` when no
component claims the path. Its `quantum_timeline` shows how a quantum-vulnerable finding was
scored, and is `null` at other levels: X, Y and Q, whether X + Y > Q, the year the migration
would end, and what IR 8547 says then, `acceptable`, `deprecated` or `disallowed`.
`years_to_quantum` goes negative once the quantum year has passed.

```json
{
  "path": "src/payments/sign.c",
  "line": 42,
  "symbol": "RSA_generate_key_ex",
  "algorithm": "RSA",
  "key_size": 2048,
  "primitive": "unspecified",
  "risk": "QUANTUM_VULNERABLE",
  "expires": null,
  "priority": {
    "score": 89,
    "component": "payments",
    "quantum_timeline": {
      "secrecy_years": 25,
      "migration_years": 7,
      "years_to_quantum": 9,
      "exposed": true,
      "migration_ends": 2033,
      "ir8547": "deprecated"
    }
  }
}
```

The document's `schema_version` is 2. It went up from 1 when `line` could become `null`, and
`priority` was added without changing it, as nothing a consumer already read changed.

The `cbom` format has one component for each mix of algorithm, key size and primitive, and its
occurrences list where that mix is used. CycloneDX has no field for the risk, so it's in the
`pqscan:risk` property, and an unresolved size is in `pqscan:key-size`. `pqscan:priority` is the
highest priority among the occurrences, since one algorithm can be used by code whose data must
stay secret for different times. An occurrence from a
certificate says when it expires in `additionalContext`, as `expires 2031-05-01T12:00:00Z`.

In `sarif`, each algorithm is one rule, named like `pqscan/RSA`. `CLASSICALLY_WEAK` and
`QUANTUM_VULNERABLE` are errors, `REVIEW` is a warning and `OK` is a note. Paths are URIs: bytes
that aren't plain in a URI are percent-encoded, and a leading `./` is dropped so that code
scanning can match them to the repository. A result about a whole file has no `region`, and one
from a certificate has its expiry in `properties.expires`. A result's `rank` is its priority,
and `properties.component` names its component, if one claims it.

Text fields use the same `\xNN` escapes as the text report, except for SARIF paths. A `\xNN`
in a `json` or `cbom` path is literal text, with its backslash, so a parser never sees invalid
UTF-8.

## Baselines and CI

A project with findings today can still stop new ones from coming in. A baseline lists the
findings a project accepts, and `--diff` reports only the others:

```sh
pqscan --write-baseline .pqscan-baseline.json .   # accept what is there now, and commit the file
pqscan --diff .pqscan-baseline.json .             # later, exits 1 only on new findings
```

```json
{
  "schema_version": 1,
  "findings": [
    {
      "path": "src/keys.c",
      "algorithm": "RSA",
      "symbol": "RSA_generate_key_ex",
      "primitive": "unspecified",
      "key_size": 2048,
      "count": 2
    }
  ]
}
```

An entry names a finding by its path, without a leading `./`, its algorithm, symbol, primitive
and key size, as the [JSON report](#reports) writes them. `count` says how many such findings the
file may have, 1 if it's left out. The line isn't part of it, so editing code above a finding
doesn't make it new. Neither are the risk and the priority, which depend on the rules and the
date. A third identical call in a file that had two is one new finding, reported at the last
of the three. Entries are sorted and identical findings share one, so the file only changes
when the findings do. pqscan refuses the whole file on any mistake, as for rules.

With `--diff`, the findings the baseline accepts are gone from the report and from the exit code,
in every format. Entries no finding used are counted on stderr: refresh the baseline then, or
the call would pass unnoticed if it came back. Paths match the way a report prints them, so
write and use a baseline from the same directory with the same `PATH` arguments. A baseline is
only read when `--diff` names it.

`--write-baseline` reports every finding as usual, and exits as a diff against the new file
would: 0, or 4 if the scan was incomplete, since the baseline then misses what was skipped.

### GitHub Action

The action builds pqscan, scans, uploads the SARIF report to code scanning, and fails the job on
findings at or above `fail-on`. With a baseline, only new findings fail it, while code scanning
still gets every finding: it compares a pull request with its base branch by itself, and would
otherwise mark the accepted findings as fixed. On Linux the action installs OpenSSL's headers if
they're missing.

```yaml
name: pqscan

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write # to upload the report to code scanning

jobs:
  pqscan:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v7
      - uses: HarenaFiantso/pqscan@v0.9.0
        with:
          baseline: .pqscan-baseline.json
```

| Input | Meaning |
| --- | --- |
| `paths` | Files and directories to scan, separated by spaces. The default is `.`. |
| `baseline` | A baseline file. When set, only the findings it doesn't accept fail the job. |
| `fail-on` | As `--fail-on`. The default is `REVIEW`. |
| `args` | More options, separated by spaces, such as `--ignore third_party --project ci/pqscan.json`. |
| `sarif-file` | Where to write the report. The default is `pqscan.sarif`. |
| `upload-sarif` | `false` to skip code scanning, which needs `security-events: write`. The default is `true`. |
| `category` | The code scanning category. The default is `pqscan`. |

The `exit-code` output is the exit code the gate went by. A scan that exits 2 or 3 uploads
nothing. The log shows the new findings, and the runner reads no workflow command while pqscan
writes to it, since a file name could pass for one.

### Gating pull requests

A pull request can edit the baseline it's checked against, and so accept its own findings. Read
the baseline from the base branch instead, so that only a reviewed and merged baseline counts:

```yaml
name: pqscan gate

on: pull_request

permissions:
  contents: read
  security-events: write

jobs:
  gate:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v7
      - name: Read the baseline of the base branch
        env:
          BASE_REF: ${{ github.base_ref }}
        run: |
          git fetch --depth=1 origin "$BASE_REF"
          git show FETCH_HEAD:.pqscan-baseline.json > "$RUNNER_TEMP/baseline.json"
      - uses: HarenaFiantso/pqscan@v0.9.0
        with:
          baseline: ${{ runner.temp }}/baseline.json
          upload-sarif: ${{ !github.event.pull_request.head.repo.fork }}
```

Pull requests from forks get a read-only token, so code scanning can't take their report, which
is what the last line is for: the job still fails on new findings. Make the gate a required
status check in the branch protection rules of `main`, and give `.pqscan-baseline.json` an owner
in `CODEOWNERS`, so that accepting a finding takes a review. To accept a finding on purpose, run
`pqscan --write-baseline .pqscan-baseline.json .` on the branch that adds it, and merge the new
baseline first, in a pull request of its own: an entry no finding uses yet is only a warning.

## Rules

The built-in rules live in [rules/default.json](rules/default.json) and are compiled into
the binary. `--rules FILE` replaces them with a file of the same format:

```json
{
  "schema_version": 1,
  "algorithms": [
    {"name": "RSA", "risk": "QUANTUM_VULNERABLE", "weak_below_bits": 2048},
    {"name": "MD5", "risk": "CLASSICALLY_WEAK"}
  ],
  "rules": [
    {"pattern": "RSA_sign", "kind": "function", "algorithm": "RSA", "primitive": "signature"},
    {"pattern": "EVP_PKEY_RSA", "kind": "constant", "algorithm": "RSA", "primitive": "unspecified"},
    {"pattern": "MD5", "kind": "function", "algorithm": "MD5", "primitive": "hash", "call_only": true},
    {"pattern": "RSA", "kind": "string", "algorithm": "RSA", "primitive": "unspecified"},
    {"pattern": "ffdhe2048", "kind": "config", "algorithm": "DH", "primitive": "key_exchange", "key_bits": 2048},
    {"pattern": "rsaEncryption", "kind": "key", "algorithm": "RSA", "primitive": "unspecified"}
  ],
  "calls": [
    {"name": "RSA_generate_key_ex", "key_bits_argument": 1},
    {"name": "EVP_PKEY_CTX_new_from_name", "algorithm_argument": 1}
  ]
}
```

| Section | Field | Meaning |
| --- | --- | --- |
| `algorithms` | `name` | The normalized name shown in reports. |
| | `risk` | `OK`, `REVIEW`, `QUANTUM_VULNERABLE` or `CLASSICALLY_WEAK`. |
| | `weak_below_bits` | Optional. Shorter keys are `CLASSICALLY_WEAK`. |
| `rules` | `pattern` | The identifier, string or name to find. |
| | `kind` | `function`, `constant` or `macro` for source identifiers, where `function` names are also looked up among the symbols of ELF binaries, `string` for an algorithm name passed to a call, `config` for a name in a TLS or SSH setting, or `key` for OpenSSL's short name of a key or digest type in a certificate or key. |
| | `algorithm` | A name declared in `algorithms`. |
| | `primitive` | `signature`, `key_exchange`, `encryption`, `hash` or `unspecified`. |
| | `call_only` | Optional, for functions. Count the name only when it's called. |
| | `key_bits` | Optional, for `config` rules. The key size the name itself fixes, as in `ffdhe2048`. |
| `calls` | `name` | A function whose arguments are worth reading. |
| | `key_bits_argument` | Optional. Position of the key size, from 0. |
| | `algorithm_argument` | Optional. Position of a string naming an algorithm, from 0. |

A `string` pattern only counts as an argument of a call listed in `calls`. `string`, `config`
and `key` patterns ignore case, and each kind has its own names, so one pattern can mean one
thing in source and another in a config file. A `key` pattern is the name OpenSSL gives the
type, such as `rsaEncryption`, `id-ecPublicKey`, `ED25519` or `SHA1`.
pqscan refuses the whole file on any mistake, such as an unknown field, and names the entry
at fault.

## Roadmap

- **Evaluation:** a corpus of open-source C projects with hand-labeled findings, measured
  precision and recall, fuzzing of every parser, and performance targets for large repositories.
- **Release:** a changelog, a man page, a static build and a Docker image.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
