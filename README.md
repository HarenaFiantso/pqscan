# pqscan

[![CI](https://github.com/HarenaFiantso/pqscan/actions/workflows/ci.yml/badge.svg)](https://github.com/HarenaFiantso/pqscan/actions/workflows/ci.yml)

pqscan is a command-line tool, written in C, that finds cryptography quantum computers
will break across C/C++ source, configuration files, certificates and ELF binaries.

![pqscan reporting RSA, DSA, DH, MD5 and AES-128 in a sample directory, then skipping a file with --ignore](assets/demo.gif)

A large enough quantum computer running Shor's algorithm would break RSA, ECDSA, EdDSA,
ECDH, DH and DSA, and NIST plans to deprecate them after 2030 and disallow them after 2035.
pqscan exists because you can't migrate what you can't find: it shows where that
cryptography is and how urgently each use needs to be replaced.

## Status

Early development. pqscan scans C/C++ source for known OpenSSL identifiers. The scan is a
plain text match for now, so it also reports identifiers in comments and strings, and it
does not read key sizes yet.

## Build and test

You need CMake 3.20 or newer and a C11 compiler (GCC or Clang), on Linux or macOS. If you
have Docker, `docker compose run --rm dev` opens a Linux shell with everything installed.

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
never followed, and only `.c`, `.h`, `.cpp` and `.hpp` files are scanned. Each finding is
one line:

```text
src/keys.c:42: RSA (QUANTUM_VULNERABLE)
```

| Option | Meaning |
| --- | --- |
| `-i`, `--ignore PATTERN` | Skip paths matching a glob. Repeatable. `.git` is always skipped. |
| `-h`, `--help` | Show the help and exit. |
| `-V`, `--version` | Show the version and exit. |

Paths that can't be read are skipped with a warning on stderr, as are files that contain
a NUL byte or exceed 64 MiB.

| Exit code | Meaning |
| --- | --- |
| 0 | No findings |
| 1 | Findings reported |
| 2 | Usage error, such as a path that doesn't exist |
| 3 | Internal error |

## Roadmap

- **Source scanning:** syntax-aware detection in C/C++, driven by external rules, that
  resolves key sizes where it can.
- **Reports:** text, JSON, CycloneDX CBOM and SARIF output.
- **Configs, certificates and keys:** OpenSSL, nginx, Apache and SSH settings, plus PEM
  and DER files.
- **ELF binaries:** linked crypto functions found without source code.
- **Prioritization and CI:** urgency scoring from the NIST IR 8547 dates and Mosca's
  theorem, and a gate that blocks new vulnerable crypto in pull requests.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
