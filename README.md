# pqscan

[![CI](https://github.com/HarenaFiantso/pqscan/actions/workflows/ci.yml/badge.svg)](https://github.com/HarenaFiantso/pqscan/actions/workflows/ci.yml)

pqscan is a command-line tool, written in C, that finds cryptography quantum computers
will break across C/C++ source, configuration files, certificates and ELF binaries.

A large enough quantum computer running Shor's algorithm would break RSA, ECDSA, ECDH, DH
and DSA, and NIST plans to deprecate them after 2030 and disallow them after 2035.
pqscan exists because you can't migrate what you can't find: it shows where that
cryptography is and how urgently each use needs to be replaced.

## Status

Early development. The build, test and CI tooling is in place, but pqscan cannot scan
anything yet.

## Build and test

You need CMake 3.20 or newer and a C11 compiler (GCC or Clang), on Linux or macOS. If you
have Docker, `docker compose run --rm dev` opens a Linux shell with everything installed.

```sh
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

The `debug` preset builds with ASan and UBSan, `release` is optimized, and `valgrind` also
runs each test under a memory checker. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
full developer setup.

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
