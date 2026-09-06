#!/usr/bin/env bash
#
# Builds statically-linked innernet/innernet-server binaries, plus a rosenpass binary, for both
# amd64 (x86_64) and arm64 (aarch64) Linux, so you can copy them straight onto nodes of either
# architecture with no runtime dependencies to install.
#
# Uses the musl target for innernet/innernet-server (not glibc): this project's Cargo.toml only
# enables rusqlite's "bundled" (statically-linked SQLite) feature for `target_env = "musl"` - on
# a glibc target the binary would dynamically link the build machine's system libsqlite3, which
# your nodes would then also need installed at a compatible version. musl avoids that entirely;
# the resulting binaries have no dynamic dependencies at all (verify with `ldd`, which reports
# "not a dynamic executable").
#
# Cross-compiles innernet/innernet-server via Docker (messense/rust-musl-cross images) - no local
# Rust cross-toolchain or rustup required, only Docker.
#
# rosenpass is built separately (see bin/Dockerfile for why it can't use the same musl-cross
# recipe - a real bindgen/musl incompatibility, not a config issue) via `docker buildx build
# --platform`, natively per architecture (QEMU-emulated for whichever isn't the host's own), with
# libsodium statically embedded. Set SKIP_ROSENPASS=1 to skip it (it's slower than the
# innernet/innernet-server build, especially the emulated architecture).

set -euo pipefail

die() {
    echo >&2 "$@"
    exit 1
}

command -v docker >/dev/null 2>&1 || die "docker is required but not found on PATH."

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="${OUT_DIR:-bin/dist}"
CARGO_CACHE_VOLUME="innernet-build-cargo-registry-cache"
ROSENPASS_VERSION="${ROSENPASS_VERSION:-0.2.3}"
SKIP_ROSENPASS="${SKIP_ROSENPASS:-}"

if [ -z "$SKIP_ROSENPASS" ]; then
    docker buildx version >/dev/null 2>&1 || die "docker buildx is required to build rosenpass (or set SKIP_ROSENPASS=1 to skip it)."
fi

# target triple -> docker image tag suffix (innernet/innernet-server cross-compile)
declare -A TARGETS=(
    ["x86_64-unknown-linux-musl"]="x86_64-musl"
    ["aarch64-unknown-linux-musl"]="aarch64-musl"
)

# target triple -> docker buildx platform (rosenpass native-per-arch build)
declare -A ROSENPASS_PLATFORMS=(
    ["x86_64-unknown-linux-musl"]="linux/amd64"
    ["aarch64-unknown-linux-musl"]="linux/arm64"
)

for target in "${!TARGETS[@]}"; do
    image_tag="${TARGETS[$target]}"
    image="messense/rust-musl-cross:${image_tag}"

    echo "==> Building for ${target} (via ${image})..."
    docker pull --quiet "$image" >/dev/null

    # Build and strip in the same container: the host's own `strip` can't handle a
    # foreign-architecture binary (e.g. stripping an arm64 binary on an amd64 host fails outright
    # with "Unable to recognise the architecture" - verified empirically, it fails cleanly rather
    # than corrupting the binary, but silently produces an unstripped binary if you don't notice).
    # Each cross image ships the matching target's own strip as `<target>-strip`.
    docker run --rm \
        -v "$REPO_ROOT":/home/rust/src \
        -v "$CARGO_CACHE_VOLUME":/root/.cargo/registry \
        "$image" \
        bash -c "cargo build --release --locked --target '$target' -p innernet-server -p innernet && '${target}-strip' 'target/$target/release/innernet' 'target/$target/release/innernet-server'"

    arch_out_dir="$OUT_DIR/$target"
    mkdir -p "$arch_out_dir"
    cp "target/$target/release/innernet" "$arch_out_dir/innernet"
    cp "target/$target/release/innernet-server" "$arch_out_dir/innernet-server"

    if [ -z "$SKIP_ROSENPASS" ]; then
        platform="${ROSENPASS_PLATFORMS[$target]}"
        echo "==> Building rosenpass ${ROSENPASS_VERSION} for ${target} (via ${platform}, this is the slow one)..."
        docker buildx build \
            --platform "$platform" \
            --build-arg "ROSENPASS_VERSION=$ROSENPASS_VERSION" \
            -f bin/Dockerfile \
            -o "type=local,dest=$arch_out_dir" \
            bin/
        chmod +x "$arch_out_dir/rosenpass"
    fi

    echo "==> ${target} binaries ready in ${arch_out_dir}/:"
    ls -la "$arch_out_dir"
    file "$arch_out_dir"/* 2>/dev/null || true
    echo
done

echo "Done. Copy the binaries for each node's architecture from ${OUT_DIR}/<target>/, e.g.:"
echo "  scp ${OUT_DIR}/aarch64-unknown-linux-musl/{innernet-server,rosenpass} root@arm-node:/usr/local/bin/"
echo "  scp ${OUT_DIR}/x86_64-unknown-linux-musl/{innernet-server,rosenpass} root@amd64-node:/usr/local/bin/"
