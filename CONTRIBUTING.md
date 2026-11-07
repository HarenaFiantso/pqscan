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

Follow [docs/code-style.md](docs/code-style.md). Formatting is automatic: run
`clang-format -i <file>`, or let the `pre-commit` hook tell you what to fix.

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
