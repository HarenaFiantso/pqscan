# Changelog

Every notable change to pqscan is listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), as [Versioning](README.md#versioning)
explains for pqscan.

## [Unreleased]

## [1.0.0] - 2026-11-08

### Added

- A `pqscan(1)` man page, which a test keeps in step with `--help`.
- `cmake --install`, which installs the binary, the man page, a copy of the built-in rules in
  `share/pqscan/default.json`, and the licenses of the code compiled into the binary.
- A static build, with the `static` preset: a fully static binary on Linux, built against musl,
  and a binary with libcrypto linked in on macOS.
- Release archives for Linux on x86-64 and arm64 and for macOS on arm64, with a `SHA256SUMS`
  file and build provenance attestations.
- A Docker image, `ghcr.io/harenafiantso/pqscan`, for x86-64 and arm64, with nothing in it but
  the static binary.
- The `PQSCAN_BUILD_TESTS` CMake option, to build pqscan without its tests.
- A stability promise for the command line, the exit codes, and every file pqscan reads or
  writes. See [Versioning](README.md#versioning).

### Changed

- The GitHub Action no longer downloads and builds the tests, so it starts sooner.

### Fixed

- `cmake --install` no longer installs the Unity test framework.
- The evaluation corpus retries its downloads, falls back to github.com, and takes HAProxy
  from HAProxy's own release archive.

## [0.10.0] - 2026-11-08

### Added

- An evaluation on six open-source projects that use OpenSSL, with hand-labeled findings,
  precision and recall, and time and memory targets, which CI checks.
- Rules for the OpenSSL API around keys, such as reading, writing, comparing and printing them,
  not only for their creation.
- Rules can fix a key size, so that `DH_get_2048_256` or `NID_secp384r1` report one.
- EC point encodings are reported.
- Every parser of untrusted input has a libFuzzer target, which CI runs for two minutes on each
  change and for half an hour every night.

### Fixed

- A signature made with an EC key reports ECDSA rather than EC.

## [0.9.0] - 2026-11-08

### Added

- Baselines: `--write-baseline` writes the findings a project accepts, and `--diff` reports
  only the others.
- A GitHub Action that scans, uploads the SARIF report to code scanning, and fails the job on
  findings, or on new findings only with a baseline.
- `PQSCAN_WARNINGS_AS_ERRORS`, so that a build that only installs pqscan does not stop on a
  warning a newer compiler adds.

### Fixed

- Dependency archives are fetched from codeload.github.com when github.com fails.

## [0.8.0] - 2026-11-08

### Added

- A priority from 0 to 100 for every finding, from the NIST IR 8547 dates and Mosca's theorem.
  Reports list the most urgent first.
- The `.pqscan.json` project file, which says how long data must stay secret, per component.
- `--project` and `--as-of`.

## [0.7.0] - 2026-11-08

### Added

- ELF binaries: the symbol tables of 64-bit ELF files, in either byte order, are matched
  against the function rules. ELF files are recognized by their first four bytes.

## [0.6.0] - 2026-11-08

### Added

- TLS and SSH configuration: OpenSSL, nginx, Apache and OpenSSH settings that list algorithms.
- Certificates, certificate requests, keys and parameters, in PEM or DER, decoded with
  OpenSSL's libcrypto, with their key size and expiry.
- Findings about a whole file, which have no line.
- A website on GitHub Pages.

### Changed

- pqscan now needs OpenSSL 3.0 or newer.
- The JSON report's `schema_version` is 2, since `line` can be `null`.

## [0.5.0] - 2026-11-07

### Added

- JSON, CycloneDX 1.6 CBOM and SARIF 2.1.0 reports, chosen with `--format`.
- `--fail-on`, the lowest risk level that makes pqscan exit 1.
- The text report ends with a count of findings by risk level.

## [0.4.1] - 2026-11-07

### Added

- Exit code 4, for a scan that found nothing to fail on but could not analyze everything in
  scope.
- `--max-time`, after which pqscan starts on no new file.
- The other common C++ extensions: `.cc`, `.cxx`, `.C`, `.hh`, `.hxx`, `.ipp`, `.inl` and `.tcc`.

### Fixed

- Macros that write their argument, writes through parentheses, hidden names and narrowing
  casts no longer leave a stale key size.
- Callees are found through parentheses and template arguments.
- Ignore patterns also match relative to each path argument.

### Security

- File names and other text from the scanned repository are escaped in reports and
  diagnostics, so they can no longer forge a report line or send escape sequences to a
  terminal.
- One NUL byte can no longer hide a file from a CI gate, since a skipped file now makes the
  scan incomplete.

## [0.4.0] - 2026-11-07

### Added

- Constants are followed inside a file: locals, `#define`s, `const` and `constexpr` globals, and
  `+`, `-`, `*` and `<<`, with overflow checks. A value that cannot be proven is `unknown`.

## [0.3.0] - 2026-11-07

### Added

- Rules in JSON, built into the binary, and `--rules` to replace them.
- Classification by key size, so that RSA, DSA and DH under 2048 bits are `CLASSICALLY_WEAK`.
- The primitive of each finding: signature, key exchange, encryption, hash or unspecified.

## [0.2.0] - 2026-11-07

### Added

- C and C++ source is parsed with Tree-sitter, so comments and unrelated strings are no longer
  reported.
- Key sizes and algorithm names are read from the literal arguments of known calls.

### Fixed

- The one-shot `MD5` and `SHA1` calls are reported.

## [0.1.0] - 2026-11-07

### Added

- The `pqscan` command, with `--help`, `--version`, `--ignore` and its exit codes.
- A recursive directory walk that never follows symbolic links.
- A text scan of C and C++ source for known OpenSSL identifiers, and a plain-text report.

[Unreleased]: https://github.com/HarenaFiantso/pqscan/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/HarenaFiantso/pqscan/compare/v0.10.0...v1.0.0
[0.10.0]: https://github.com/HarenaFiantso/pqscan/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/HarenaFiantso/pqscan/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/HarenaFiantso/pqscan/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/HarenaFiantso/pqscan/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/HarenaFiantso/pqscan/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/HarenaFiantso/pqscan/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/HarenaFiantso/pqscan/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/HarenaFiantso/pqscan/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/HarenaFiantso/pqscan/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/HarenaFiantso/pqscan/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/HarenaFiantso/pqscan/releases/tag/v0.1.0
