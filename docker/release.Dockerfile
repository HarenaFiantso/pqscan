# SPDX-License-Identifier: Apache-2.0
#
# The release image, and the static Linux binary of the release archives. Alpine's C library,
# musl, can be linked in whole, unlike glibc, so the binary needs no library at run time and the
# image holds nothing else.
#
#   docker build -f docker/release.Dockerfile -t pqscan .                     the image
#   docker build -f docker/release.Dockerfile --target dist --output dist .   the installed files

# The digest is the multi-arch index, so this builds natively on arm64 and x86-64.
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS build

RUN apk add --no-cache build-base cmake file mandoc openssl-dev openssl-libs-static

WORKDIR /src
COPY . .
# Every test runs against musl before anything ships, since it differs from glibc and macOS.
RUN cmake --preset static \
    && cmake --build --preset static --parallel \
    && ctest --preset static --parallel 4 \
    && cmake --install build/static --strip --prefix /dist

FROM scratch AS dist
COPY --from=build /dist /

FROM scratch
LABEL org.opencontainers.image.title="pqscan" \
      org.opencontainers.image.description="Find quantum-vulnerable cryptography in C/C++ source, configs, certificates and ELF binaries" \
      org.opencontainers.image.source="https://github.com/HarenaFiantso/pqscan" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /dist /usr/local
# nobody: the scanned tree is mounted read-only, and pqscan needs no privilege to read it.
USER 65534:65534
WORKDIR /src
ENTRYPOINT ["/usr/local/bin/pqscan"]
CMD ["."]
