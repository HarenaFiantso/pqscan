# Contributing to pqscan

## Development setup

You need CMake 3.20 or newer, a C11 compiler, OpenSSL 3.0 or newer with its headers,
`clang-format`, `clang-tidy`, `cppcheck` and `check-jsonschema`. OpenSSL is the one library
taken from the system rather than downloaded by CMake. `clang-format`, `clang-tidy` and
`check-jsonschema` are pinned in `requirements-dev.txt` so that your results match CI.

On macOS, with the Xcode command line tools installed:

```sh
brew install cmake cppcheck openssl@3 pipx
xargs -n 1 pipx install < requirements-dev.txt
```

On Debian or Ubuntu:

```sh
sudo apt-get install build-essential clang cmake cppcheck libssl-dev pipx valgrind
xargs -n 1 pipx install < requirements-dev.txt
```

Then enable the git hooks in your clone:

```sh
scripts/setup-hooks.sh
```

The hooks check your work at three points:

| Hook | What it checks |
| --- | --- |
| `pre-commit` | Staged C files match `clang-format` |
| `commit-msg` | The message follows Conventional Commits and has no attribution trailers |
| `pre-push` | The `debug` preset builds, and all tests pass |

### Linux container (optional)

With Docker installed, you can work in the same Linux environment as CI, whatever your
host. This is how to run real Valgrind on a Mac. Your source tree is mounted into the
container, and the first run builds the image.

```sh
docker compose run --rm dev              # open a shell in the container
```

All the commands below work unchanged in that shell. It builds with Clang by default. To
switch to GCC, reconfigure with `CC=gcc cmake --preset debug --fresh`.

Container builds live in a Docker volume, not in your `build/` directory, so they never
touch your native builds. Run `docker compose build` after changing `requirements-dev.txt`
or the Dockerfile, and `docker compose down --volumes` to delete the container's builds.

## Workflow

1. Create a branch from `main`, such as `feat/detect-ec-key`.
2. Make small commits, one logical change each.
3. Open a pull request against `main` and fill in the checklist.
4. Merge once CI is green and the review is approved.

## Code style

These rules apply to all code in this repository. Formatting is automatic: run
`clang-format -i <file>`, or let the `pre-commit` hook tell you what to fix. The checks
below enforce what they can, and reviewers check the rest.

### Clean Code (Robert C. Martin)

* **Names tell the truth.** `count_vulnerable_calls()` instead of `process()`. Only use well-known abbreviations (`buf`, `len`, `fd`).
* **Small functions that do one thing.** Aim for under \~20 lines. If a function has "sections", split it.
* **Few arguments**, three at most. Use a struct beyond that.
* **No hidden side effects.**
* **No magic numbers.** Use named constants or enums.
* **DRY.** Shared logic lives in one place.
* **One level of abstraction per function.**
* **Handle errors explicitly** with early returns, without burying the main path.
* **Single responsibility per module**, and depend on interfaces (function-pointer structs), not concrete modules.
* **Boy Scout rule:** leave code cleaner than you found it, with refactors in separate commits.

### Writing good C

* Compile with `-std=c11 -Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion -Wstrict-prototypes`. Debug builds add `-fsanitize=address,undefined`.
* **Every allocation has one owner.** The header says who frees what. Pair every `x_create` with an `x_destroy`.
* Check every return value. Never ignore an error.
* Never use `strcpy`, `strcat`, `sprintf` or `gets`. Use `snprintf` and functions that take a length, and pass buffer sizes explicitly.
* Use `const` wherever it applies, `size_t` for sizes and indexes, and watch signed/unsigned conversions and integer overflow on any size arithmetic.
* Make internal symbols `static`. Avoid mutable global state.
* Start every C file with `/* SPDX-License-Identifier: Apache-2.0 */`, and every shell or CMake file with `# SPDX-License-Identifier: Apache-2.0`.
* Use include guards, and have each header include only what it needs.
* Free in reverse order of allocation. `goto cleanup` is fine for that.
* **This tool reads untrusted input** (arbitrary repos and binaries). Never execute anything it scans, and bounds-check every read.
* Prefer clear code over clever code. Use functions, not macro tricks.

### Documentation and comments

* Document every public function in its header with a short Doxygen block: purpose, parameters, return value, error cases, and **memory ownership**.
* In `.c` files, comment **only** what the code can't say: a non-obvious algorithm, tricky pointer work, a format quirk (ELF, DER, SARIF), a workaround, or a "why". Never paraphrase code line by line.
* If a block needs a comment, first try a better name or extracting a function.
* **No `docs/` folder.** Documentation lives in `README.md`, `CONTRIBUTING.md` and header comments.
* The website in `site/` presents the README to a wider audience and never replaces it. Update it when options, exit codes or report formats change.
* Record significant design decisions in the commit message and pull request description. A "why" that must outlive them goes in a comment next to the code.
* Keep `README.md` current at the end of every phase.

### Tests

* No feature is done without tests. Write the test first when you can.
* Unit tests for every module, and integration tests that run the binary on `tests/fixtures/` and compare against the expected output.
* Test edge cases: empty, missing or unreadable files, huge lines, non-UTF-8 input, and identifiers in comments, strings and macros. For binaries and certificates, also test truncated or malformed input.
* When a false positive or false negative shows up, add a fixture that reproduces it before fixing it.
* Every parser (source, config, PEM/DER handling, ELF) gets a fuzz target, by phase 10 at the latest.
* Tests must be fast, independent and deterministic.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/) in the imperative:

```text
feat(scan): detect EC_KEY usage
fix(rules): ignore identifiers in comments
test(elf): add truncated header fixture
```

Allowed types are `build`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor`,
`revert`, `style` and `test`. Don't add `Co-Authored-By` or any AI attribution trailer;
the `commit-msg` hook rejects them.

## Running the checks locally

These are the same checks CI runs:

```sh
scripts/check-format.sh                  # formatting

cmake --preset debug                     # build and test with ASan and UBSan
cmake --build --preset debug
ctest --preset debug

cmake --preset release                   # optimized build
cmake --build --preset release
ctest --preset release

scripts/run-static-analysis.sh           # clang-tidy and cppcheck, after the debug configure

cmake --preset valgrind                  # memory checker
cmake --build --preset valgrind
ctest --preset valgrind
```

The `valgrind` preset uses Valgrind on Linux and Apple's `leaks` on macOS, because
Valgrind does not run on Apple Silicon. `leaks` only looks for leaks, and it can miss some
because it scans memory conservatively, so CI's Valgrind job is the final check. To catch what `leaks` misses before you push, run the preset in the
[Linux container](#linux-container-optional).

To run just the memory-checked tests, use `ctest --preset valgrind -L valgrind`.

To validate reports against the official CycloneDX and SARIF schemas, also on file names
built to break them:

```sh
cmake --preset debug -DPQSCAN_CHECK_REPORT_SCHEMAS=ON
cmake --build --preset debug
ctest --preset debug -L schema
```

## Fuzzing

Each parser of untrusted input has a fuzz target in `fuzz/`: the ELF reader, the config lexer,
the PEM block finder, the source, config and certificate scanners, and the rule, project and
baseline loaders. A target checks more than the absence of a crash: words, blocks and symbols
must lie inside the input, findings must be what reporters expect, and a refused file must come
with a message. Every build also makes a replay driver for each target, which runs it on its
seeds, on every truncation of them, and on a fixed set of seeded edits, under the sanitizers of
the preset. It is an ordinary test:

```sh
ctest --preset debug -L fuzz
```

The real fuzzer needs a Clang that ships libFuzzer. Apple's Clang doesn't, so on macOS use
Homebrew's (`brew install llvm`). On Linux, the distribution's `clang` works:

```sh
CC="$(brew --prefix llvm)/bin/clang" cmake --preset fuzz   # just `cmake --preset fuzz` on Linux
cmake --build --preset fuzz --target fuzz_cert_scanner
scripts/run-fuzzer.sh cert_scanner 300                     # seconds, 60 by default
```

`scripts/run-fuzzer.sh` gives each target its seeds and a dictionary from `fuzz/dict/`. New inputs
are kept in `build/fuzz-corpus/`, and one that crashes is written to `build/fuzz-crashes/`. CI
runs each fuzzer for two minutes, and a nightly workflow runs each for half an hour and keeps its
corpus. When a crash turns up, add the input as a fixture with a test that reproduces it before
fixing the bug.

To add a target, write `fuzz/fuzz_NAME.c` with `LLVMFuzzerTestOneInput()`, register it in
`fuzz/CMakeLists.txt` with small seeds, and add it to `scripts/run-fuzzer.sh` and to the fuzz
matrix of both workflows. A scanner can use `fuzz/scan_harness.h`. If one replay run is slow,
give it `EDITS` so the test stays under its time limit.

## Measuring precision, recall and speed

`bench/` measures pqscan on six open-source projects pinned in `bench/corpus.json`, and on the
OpenSSL source tree for speed. The projects are downloaded into `build/bench`, never committed.
It needs Python 3.9 or newer and nothing else:

```sh
cmake --preset release && cmake --build --preset release
python3 bench/bench.py fetch              # downloads about 100 MiB, once
python3 bench/bench.py evaluate --write   # precision and recall, written to bench/results.md
python3 bench/bench.py perf               # time and memory against bench/perf.json
```

A project is downloaded from GitHub's archive of its tag, unless its entry names a `url`. Give
a `url` to the project's own release archive when its `.gitattributes` marks a file
`export-subst`: GitHub fills such a file in when it builds the archive, and the result differs
between its servers, so the archive's SHA-256 does too. HAProxy is pinned this way.

`bench/labels/` holds the labels the rules were tuned on, and `bench/labels/held-out/` labels made
afterwards from files no rule was tuned on. Keep it that way: when a held-out miss leads to a new
rule, say in the commit that the set is no longer blind, and label fresh files for the next
measurement.

### How to label

A label is one line of code and the algorithm used there:

```json
{"line": 130, "algorithm": "RSA"}
{"line": 50, "algorithm": "EC", "key_size": 384}
```

* **Label** a line of C or C++ that uses an OpenSSL identifier specific to an algorithm pqscan
  grades: a call, a function used as a value, a constant such as `EVP_PKEY_RSA` or
  `NID_secp384r1`, or an algorithm name passed to an API, as in
  `EVP_get_digestbyname("sha1")`. Macro bodies count, as they are code once expanded.
* **Don't label** comments, preprocessor conditions, type names in declarations, `*_free` and
  `*_up_ref` calls, error and result codes such as `SSL_R_*` or `DH_CHECK_*`, buffer sizes
  such as `MD5_DIGEST_LENGTH`, strings that are not passed to an API (log messages, JSON
  keys), a project's own names that merely look like OpenSSL's, or other libraries' APIs.
* Name the algorithm the identifier itself names: `EC_KEY_*` is EC, `ECDH_compute_key` is ECDH,
  `ECDSA_SIG_*` is ECDSA. Give a key size only when the line fixes it.
* A line counts once per algorithm, and an argument on a later line of a call that is already
  labeled is not labeled again.
* For a certificate or key, take the key type, size and signature algorithm from
  `openssl x509 -text` or `openssl pkey -text`, never from pqscan. A certificate has one label
  for its key and one for its signature, at the line of its BEGIN marker, or `null` for DER.
* List files with no crypto use too, with `[]`, so that false positives are counted.

Find candidates with a search wider than the rules, such as every identifier that starts with
`RSA_`, `EC_` or `NID_`, then read each one in its context. Never label from pqscan's output.

## Updating the README demo

The GIF in the README is recorded from `assets/demo.tape` with [VHS](https://github.com/charmbracelet/vhs).
Record it again when the CLI's output changes:

```sh
brew install vhs                         # also installs ttyd and ffmpeg
cmake --preset release
cmake --build --preset release
vhs assets/demo.tape
```

## Updating the website

The [website](https://harenafiantso.github.io/pqscan/) is one hand-written page in `site/`, with
no framework. It's published to GitHub Pages when a change to `site/` reaches `main`, and it
needs Python 3 and `curl` to build:

```sh
scripts/build-site.sh
python3 -m http.server --directory build/site
```

The script adds JetBrains Mono Nerd Font, pinned by hash and cut down to the glyphs the page
uses, so a new icon also has to be added to the list in the script.

The page repeats facts from the README, and its examples are real output. Update it when options,
exit codes or report formats change. The page must also read well without JavaScript and with
`prefers-reduced-motion`.

## Reporting a false positive or false negative

Open a [detection report](https://github.com/HarenaFiantso/pqscan/issues/new?template=detection_report.yml)
with the smallest code snippet that reproduces it, what you expected and what pqscan
reported.

To fix one yourself, add a fixture under `tests/fixtures/` that reproduces the problem
before changing any detection code. If it comes from a project in `bench/`, label it there too.
