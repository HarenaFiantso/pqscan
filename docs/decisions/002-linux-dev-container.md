# 002: Linux development container

## Context

CI runs on Linux and macOS, but a macOS developer can only run the macOS half locally.
The biggest gap is Valgrind: [decision 001](001-memory-checking.md) replaces it with
`leaks` on Apple Silicon, so uninitialized reads stay hidden until CI runs. Differences
between GCC and Apple Clang also only show up after a push.

## Decision

Provide an optional Linux environment, defined by `compose.yaml` and
`docker/dev.Dockerfile`. It adds to the native setup and does not replace it: every check
still runs natively, and nothing in the build depends on Docker.

- **Same base as CI.** Ubuntu 24.04, pinned by the digest of its multi-arch index. The
  image runs natively on the host's architecture, so Apple Silicon needs no emulation.
- **Tools only.** The source tree is bind-mounted, not copied, so edits on the host are
  seen immediately and the image only changes when the tools do.
- **A separate build directory.** Presets write to `build/` inside the source tree, so a
  plain bind mount would mix the host's CMake cache and Mach-O objects with the
  container's. A named volume is mounted over `build/` to keep them apart.
- **Non-root.** The container runs as UID 1000, because this tool will read untrusted
  input and files it creates on a Linux host should stay editable there.
- **Clang by default**, to match the CI static-analysis job. GCC is one variable away.
- **The name `dev.Dockerfile`** leaves room for the release image, a different thing: a
  small image holding only the static binary.

## Consequences

- Real Valgrind and GCC run locally on a Mac, before pushing.
- The container only provides Linux. BSD and other Unix systems would need a VM.
- On Apple Silicon the container is arm64 while CI is x86-64, so CI stays the final check.
- The base image is pinned, but its apt packages float within Ubuntu 24.04. CI installs
  them the same way, so the two stay in step.
- The image is about 1.4 GB, and `docker compose build` must be rerun after changing the
  Dockerfile or `requirements-dev.txt`.
