# innernet-rp

An innernet fork implementing the authenticated post-quantum WireGuard PSK
exchange described in [the design](docs/design.md). Development is staged by
[milestone](docs/milestones.md); this is not an audited production release.

The baseline is innernet 2.0.0, commit
`e922387122874c8182abab5b1c1e3eed2da1ba7f`, before its Rosenpass integration.
The standalone `innernet-pq` crate uses system leancrypto and OpenSSL, with
SQLite supplied by the system as well. Rust dependencies are updated to
current stable releases and the resolved versions are committed in Cargo.lock.

See [build and validation instructions](docs/implementation.md) and the
[test plan](docs/testing.md). Until the traffic-gate milestone is implemented
and tested, the crypto implementation does not enable production PQ traffic
or modify WireGuard PSKs.

## Development checks

```sh
cargo fmt --all
cargo clippy --workspace --locked --all-targets -- -D warnings
bash tests/run.sh unit
bash tests/run.sh integration
cargo test --workspace --locked --features v6-test
```

License coverage and retained upstream notices are in [LICENSE](LICENSE).
