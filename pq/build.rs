fn main() {
    println!("cargo:rerun-if-changed=native/crypto.c");
    let mut bridge = cc::Build::new();
    bridge
        .file("native/crypto.c")
        .flag("-std=c11")
        .warnings_into_errors(true);
    for (library, minimum) in [("leancrypto", "1.8.0"), ("openssl", "3.6.4")] {
        let installation = pkg_config::Config::new()
            .atleast_version(minimum)
            .statik(false)
            .probe(library)
            .unwrap_or_else(|error| {
                panic!("system shared {library} >= {minimum} required: {error}")
            });
        for include in installation.include_paths {
            bridge.include(include);
        }
        println!(
            "cargo:rustc-env=PQ_{}_VERSION={}",
            library.to_uppercase(),
            installation.version
        );
    }
    bridge.compile("innernet_pq_bridge");
}
