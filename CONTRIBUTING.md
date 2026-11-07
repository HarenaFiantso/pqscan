# Contributing to pqscan

## Development setup

You need CMake 3.20 or newer, a C11 compiler, `clang-format`, `clang-tidy` and `cppcheck`.
The two Clang tools are pinned in `requirements-dev.txt` so that your results match CI.

On macOS, with the Xcode command line tools installed:

```sh
brew install cmake cppcheck pipx
xargs -n 1 pipx install < requirements-dev.txt
```

On Debian or Ubuntu:

```sh
sudo apt-get install build-essential clang cmake cppcheck pipx valgrind
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
See [docs/decisions/002-linux-dev-container.md](docs/decisions/002-linux-dev-container.md).

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
* Record significant design decisions in the commit message and pull request description. A "why" that must outlive them goes in a comment next to the code.
* Keep `README.md` current at the end of every phase.

### Tests

* No feature is done without tests. Write the test first when you can.
* Unit tests for every module, and integration tests that run the binary on `tests/fixtures/` and compare against the expected output.
* Test edge cases: empty, missing or unreadable files, huge lines, non-UTF-8 input, and identifiers in comments, strings and macros. For binaries and certificates, also test truncated or malformed input.
* When a false positive or false negative shows up, add a fixture that reproduces it before fixing it.
* Every parser (source, config, PEM/DER handling, ELF) gets a fuzz target.
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

scripts/run-static-analysis.sh           # clang-tidy and cppcheck, after the debug configure

cmake --preset valgrind                  # memory checker
cmake --build --preset valgrind
ctest --preset valgrind
```

The `valgrind` preset uses Valgrind on Linux and Apple's `leaks` on macOS, because
Valgrind does not run on Apple Silicon. `leaks` finds leaks only, so CI's Valgrind job is
the final check. To catch what `leaks` misses before you push, run the preset in the
[Linux container](#linux-container-optional). See
[docs/decisions/001-memory-checking.md](docs/decisions/001-memory-checking.md).

To run just the memory-checked tests, use `ctest --preset valgrind -L valgrind`.

## Reporting a false positive or false negative

Open a [detection report](https://github.com/HarenaFiantso/pqscan/issues/new?template=detection_report.yml)
with the smallest code snippet that reproduces it, what you expected and what pqscan
reported.

To fix one yourself, add a fixture under `tests/fixtures/` that reproduces the problem
before changing any detection code.
