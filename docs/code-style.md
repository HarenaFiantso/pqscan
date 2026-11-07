# Code style

These rules apply to all code in this repository. `clang-format` and the checks in
[CONTRIBUTING.md](../CONTRIBUTING.md) enforce what they can; reviewers check the rest.

## Clean Code (Robert C. Martin)

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

## Writing good C

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

## Documentation and comments

* Document every public function in its header with a short Doxygen block: purpose, parameters, return value, error cases, and **memory ownership**.
* In `.c` files, comment **only** what the code can't say: a non-obvious algorithm, tricky pointer work, a format quirk (ELF, DER, SARIF), a workaround, or a "why". Never paraphrase code line by line.
* If a block needs a comment, first try a better name or extracting a function.
* Record significant design decisions in `docs/decisions/NNN-title.md` (context, decision, consequences).
* Keep `README.md` current at the end of every phase.

## Tests

* No feature is done without tests. Write the test first when you can.
* Unit tests for every module, and integration tests that run the binary on `tests/fixtures/` and compare against the expected output.
* Test edge cases: empty, missing or unreadable files, huge lines, non-UTF-8 input, and identifiers in comments, strings and macros. For binaries and certificates, also test truncated or malformed input.
* When a false positive or false negative shows up, add a fixture that reproduces it before fixing it.
* Every parser (source, config, PEM/DER handling, ELF) gets a fuzz target.
* Tests must be fast, independent and deterministic.
