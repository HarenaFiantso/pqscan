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
> Early development. pqscan scans C/C++ source for known OpenSSL identifiers through its
> syntax tree, and reads literal key sizes and algorithm names. Key sizes do not change the
> risk level yet, so RSA-1024 is still reported as `QUANTUM_VULNERABLE`, and a size held in
> a variable shows as `unknown`.

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
never followed, and only `.c`, `.h`, `.cpp` and `.hpp` files are scanned. Each finding is
one line:

```text
src/keys.c:42: RSA-2048 (QUANTUM_VULNERABLE)
src/keys.c:57: RSA-unknown (QUANTUM_VULNERABLE)
src/hash.c:12: MD5 (CLASSICALLY_WEAK)
```

The number is the key size. `unknown` means the algorithm has one, but it isn't a literal
in the source.

pqscan parses each file with [Tree-sitter](https://tree-sitter.github.io), so broken code
is still scanned:

* **Reported:** calls and other uses of known identifiers, including in macro bodies and in
  every branch of `#ifdef`, plus algorithm names passed to known calls, such as `"RSA"` in
  `EVP_PKEY_CTX_new_from_name`.
* **Reported only when called:** `MD5` and `SHA1`, since those names are also common enum
  values and variables.
* **Not reported:** comments, other strings, declarations such as prototypes, struct fields,
  C++ methods, and code under a literal `#if 0`.

| Option | Meaning |
| --- | --- |
| `-i`, `--ignore PATTERN` | Skip paths matching a glob. Repeatable. `.git` is always skipped. |
| `-h`, `--help` | Show the help and exit. |
| `-V`, `--version` | Show the version and exit. |

> [!NOTE]
> Paths that can't be read are skipped with a warning on stderr, as are files that contain
> a NUL byte, exceed 64 MiB, or take more than 30 seconds to scan.

| Exit code | Meaning |
| --- | --- |
| 0 | No findings |
| 1 | Findings reported |
| 2 | Usage error, such as a path that doesn't exist |
| 3 | Internal error |

> [!CAUTION]
> Exit code 0 doesn't prove the code is free of vulnerable cryptography. pqscan only
> recognizes the OpenSSL identifiers it knows about, in C/C++ source files.

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
