# M3 Docker scenario image: like Dockerfile.runtime, but also compiles in
# the pq-dev-harness feature (client + server) so the real exchange engine
# can be driven end to end without waiting for M4 to lift --enable-pq-psk's
# production refusal. Never used for anything but this test image.
FROM innernet-pq-build:m0
RUN pacman -Sy --noconfirm --needed curl
COPY . /work
RUN cargo build --workspace --locked --features pq-dev-harness
