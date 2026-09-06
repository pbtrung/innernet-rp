# Builds the `rosenpass` binary (https://github.com/rosenpass/rosenpass) with libsodium
# statically embedded, for use alongside innernet's own musl-static innernet/innernet-server
# binaries (built separately, see build-multiarch.sh - that one doesn't need this Dockerfile at
# all, since innernet itself has no C library dependencies like this).
#
# Why not fully static (musl): rosenpass depends on oqs-sys, which uses bindgen, which loads
# libclang via dlopen() *at build time*. Rust defaults to fully-static binaries on musl targets
# (crt-static), including the build-script helper binary itself - and a statically-linked
# binary cannot dlopen() anything, full stop. This is a real bindgen/musl incompatibility, not a
# missing package. The escape hatch (disabling crt-static) would make the *final* binary
# dynamically link against musl's own libc instead - less portable for real server fleets than
# glibc, which is already present on virtually every mainstream Linux distribution.
#
# So instead: build libsodium ourselves from source, static-only (`--enable-static
# --disable-shared`, no .so installed anywhere). libsodium-sys-stable's own build.rs never asks
# pkg-config for a static link explicitly (it just calls a plain `pkg_config::Config::new().probe()`
# - verified by reading its source), so the only reliable way to get libsodium statically
# embedded is to make sure no shared alternative exists for the linker to pick instead. Verified:
# the resulting binary's `ldd` shows no libsodium dependency at all, only standard glibc
# (libc/libm/libgcc_s/ld-linux) - eliminating the actual risk that mattered (a node needing an
# exact compatible libsodium version), even though it's not a zero-dependency static binary.
#
# Usage (see build-multiarch.sh, which drives this automatically):
#   docker buildx build --platform linux/amd64 \
#     --build-arg ROSENPASS_VERSION=0.2.3 \
#     -f bin/Dockerfile -o type=local,dest=bin/dist/x86_64-unknown-linux-musl bin/

# syntax=docker/dockerfile:1
FROM rust:1-slim-bookworm AS builder

ARG ROSENPASS_VERSION=0.2.3
ARG LIBSODIUM_VERSION=1.0.20

# >= 0.2.1 fixes CVE-2023-53157 (remote DoS via unvalidated buffer size when decoding messages) -
# see doc/design.md/milestones.md in the innernet-rp repo. Never build an older version.
RUN case "${ROSENPASS_VERSION}" in \
      0.1.*|0.2.0) echo "refusing to build rosenpass ${ROSENPASS_VERSION}: predates the CVE-2023-53157 fix (>= 0.2.1 required)" >&2; exit 1 ;; \
      *) ;; \
    esac

RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
        build-essential cmake pkg-config libclang-dev clang curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /tmp/libsodium.tar.gz \
        "https://download.libsodium.org/libsodium/releases/libsodium-${LIBSODIUM_VERSION}.tar.gz" \
    && tar xzf /tmp/libsodium.tar.gz -C /tmp \
    && cd "/tmp/libsodium-${LIBSODIUM_VERSION}" \
    && ./configure --prefix=/usr/local --enable-static --disable-shared \
    && make -j"$(nproc)" \
    && make install \
    && rm -rf /tmp/libsodium*

RUN cargo install --version "${ROSENPASS_VERSION}" --locked --root /out rosenpass \
    && strip /out/bin/rosenpass

# Minimal export stage: `-o type=local,dest=...` extracts this stage's entire filesystem, so keep
# it to just the one file we actually want.
FROM scratch AS export
COPY --from=builder /out/bin/rosenpass /rosenpass
