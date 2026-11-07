# SPDX-License-Identifier: Apache-2.0
#
# Linux development image, matching the ubuntu-24.04 CI runners. It lets any host run the
# Linux checks locally, such as real Valgrind.

# The digest is the multi-arch index, so this builds natively on arm64 and x86-64.
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

# Recommended packages are skipped, so name the two the checks need: libc6-dbg, which
# Valgrind reads at startup, and libclang-rt-dev, Clang's sanitizer runtime.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        cppcheck \
        git \
        libc6-dbg \
        libclang-rt-dev \
        python3-venv \
        valgrind \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-dev.txt /tmp/requirements-dev.txt
RUN python3 -m venv /opt/dev-tools \
    && /opt/dev-tools/bin/pip install --no-cache-dir --requirement /tmp/requirements-dev.txt \
    && rm /tmp/requirements-dev.txt

# The bind-mounted repo is owned by a host user, and git refuses to work in it otherwise.
RUN git config --system --add safe.directory /work

# Created here so the named build volume starts out owned by the non-root user.
RUN mkdir --parents /work/build && chown --recursive ubuntu:ubuntu /work

ENV PATH="/opt/dev-tools/bin:$PATH"
# clang matches the CI static-analysis job. Override with CC=gcc to build with GCC.
ENV CC=clang

USER ubuntu
WORKDIR /work
CMD ["bash"]
