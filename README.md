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

## Status

> [!WARNING]
> Early development. pqscan scans C/C++ source for the OpenSSL identifiers in its rules,
> through the syntax tree, and follows constants inside a file to find key sizes and algorithm
> names. A value it can't prove shows as `unknown`.

## Build and test

You need CMake 3.20 or newer and a C11 compiler (GCC or Clang), on Linux or macOS.

> [!TIP]
> If you have Docker, `docker compose run --rm dev` opens a Linux shell with everything
> installed.

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
./build/debug/pqscan --help
```

The `debug` preset builds with ASan and UBSan, `release` is optimized, and `valgrind` also
runs each test under a memory checker. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
full developer setup.

## Usage

```sh
pqscan [OPTIONS] PATH...
```

Each `PATH` is a file or a directory. Directories are walked recursively, symlinks are
never followed, and only C and C++ sources are scanned: `.c`, `.h`, `.cpp`, `.hpp`, `.cc`,
`.cxx`, `.C`, `.hh`, `.hxx`, `.ipp`, `.inl` and `.tcc`. Each finding is one line:

```text
src/keys.c:42: RSA-2048 (QUANTUM_VULNERABLE)
src/keys.c:51: RSA-1024 (CLASSICALLY_WEAK)
src/keys.c:57: RSA-unknown (QUANTUM_VULNERABLE)
src/hash.c:12: MD5 (CLASSICALLY_WEAK)
```

The number is the key size. `unknown` means the algorithm has one, but pqscan can't prove its
value. RSA, DSA and DH keys under 2048 bits are `CLASSICALLY_WEAK`, because they are already
unsafe today. An `unknown` size keeps the algorithm's usual level.

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

| Option | Meaning |
| --- | --- |
| `-i`, `--ignore PATTERN` | Skip paths matching a glob, tried on the file name, the path, and the path relative to `PATH`. Repeatable. `.git` is always skipped. |
| `-r`, `--rules FILE` | Use the rules in this JSON file instead of the built-in ones. |
| `-h`, `--help` | Show the help and exit. |
| `-V`, `--version` | Show the version and exit. |

> [!NOTE]
> Paths that can't be read are skipped with a warning on stderr, as are files that contain
> a NUL byte, exceed 64 MiB, or take more than 30 seconds to scan.

| Exit code | Meaning |
| --- | --- |
| 0 | No findings |
| 1 | Findings reported |
| 2 | Usage error, such as a path that doesn't exist or a rule file that isn't valid |
| 3 | Internal error |

> [!CAUTION]
> Exit code 0 doesn't prove the code is free of vulnerable cryptography. pqscan only
> recognizes the identifiers in its rules, in C/C++ source files.

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
    {"pattern": "RSA", "kind": "string", "algorithm": "RSA", "primitive": "unspecified"}
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
| `rules` | `pattern` | The identifier or string to find. |
| | `kind` | `function`, `constant`, `macro` or `string`. |
| | `algorithm` | A name declared in `algorithms`. |
| | `primitive` | `signature`, `key_exchange`, `encryption`, `hash` or `unspecified`. |
| | `call_only` | Optional, for functions. Count the name only when it's called. |
| `calls` | `name` | A function whose arguments are worth reading. |
| | `key_bits_argument` | Optional. Position of the key size, from 0. |
| | `algorithm_argument` | Optional. Position of a string naming an algorithm, from 0. |

A `string` pattern only counts as an argument of a call listed in `calls`, and ignores case.
pqscan refuses the whole file on any mistake, such as an unknown field, and names the entry
at fault.

## Roadmap

- **Reports:** text, JSON, CycloneDX CBOM and SARIF output.
- **Configs, certificates and keys:** OpenSSL, nginx, Apache and SSH settings, plus PEM
  and DER files.
- **ELF binaries:** linked crypto functions found without source code.
- **Prioritization and CI:** urgency scoring from the NIST IR 8547 dates and Mosca's
  theorem, and a gate that blocks new vulnerable crypto in pull requests.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
