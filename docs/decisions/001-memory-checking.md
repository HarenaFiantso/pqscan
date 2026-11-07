# 001: Memory checking on Linux and macOS

## Context

The project requires tests to pass under Valgrind. Valgrind does not run on Apple
Silicon, and AddressSanitizer's leak detection is not supported on macOS, so a
macOS developer would otherwise have no leak check at all.

## Decision

The `valgrind` preset picks the tool by platform:

- Linux runs each test under Valgrind, with every leak kind counted as an error.
- macOS runs each test under Apple's `leaks --atExit`, which ships with the Xcode
  command line tools.

Memory errors such as overflows and use-after-free are covered on both platforms by
ASan and UBSan in the `debug` preset.

The preset runs every test twice, plain and under the memory checker. This is
required: `leaks --atExit` exits 0 when the test it wraps fails or crashes, so a
memcheck test alone cannot detect a failing test.

## Consequences

- Leaks are caught locally on macOS instead of waiting for CI.
- `leaks` finds leaks only. Uninitialized reads are caught only by Valgrind, so the
  Valgrind job in CI stays the final check.
- The name `valgrind` is slightly inaccurate on macOS. It was kept so the preset and
  the label mean the same thing on every platform.
