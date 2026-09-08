//! M9 design case 14: a real, sustained write-attempt load driver against
//! a real running server, exercising the actual `PUT /user/pq-keys`
//! production code path (body parsing, admission control, rate limiting)
//! -- not a mock. Run from an already-installed interface with a real,
//! already-established WireGuard session to the server (the server
//! authenticates each request by source IP matching a known peer, so
//! this must run inside a real tunnel, exactly like the production
//! client does).
//!
//! Registers one real identity for real (a genuine, valid write), then
//! hammers the same endpoint with a deliberately stale `expected_revision`
//! (a guaranteed, cheap-to-reject CAS conflict) at the target rate for the
//! configured duration -- representative of "many write attempts, most
//! correctly rejected", exactly what design case 14 asks to be measured,
//! not just a happy-path throughput number.
//!
//! Usage: pq_load_harness <interface> <target-per-second> <duration-secs> <threads>
use anyhow::{Context, Error};
use innernet_client_core::rest_client::RestClient;
use innernet_client_core::DEFAULT_CONFIG_DIR;
use innernet_pq::{
    api::{AdvertisedBundle, Lifecycle, Registration},
    crypto::SystemRandom,
    protocol::{Binary, Number},
    state::Identity,
};
use innernet_shared::interface_config::InterfaceConfig;
use std::{
    env,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Barrier,
    },
    time::{Duration, Instant},
};
use wireguard_control::{InterfaceName, Key};

fn main() -> Result<(), Error> {
    let mut args = env::args().skip(1);
    let interface: InterfaceName = args
        .next()
        .context(
            "usage: pq_load_harness <interface> <target-per-second> <duration-secs> <threads>",
        )?
        .parse()?;
    let target_per_second: u64 = args.next().context("missing target-per-second")?.parse()?;
    let duration_secs: u64 = args.next().context("missing duration-secs")?.parse()?;
    let threads: u64 = args.next().context("missing threads")?.parse()?;

    let config_dir = Path::new(DEFAULT_CONFIG_DIR);
    let config = InterfaceConfig::from_interface(config_dir, &interface)?;
    let rest_client = RestClient::new(&config.server);
    let own_public_key = Key::from_base64(&config.interface.private_key)
        .map(|k| k.get_public())
        .context("deriving this interface's own public key")?;

    // A genuine, valid first registration -- one real, successful write.
    let mut rng = SystemRandom;
    let identity = Identity::generate(Binary(own_public_key.0), Number::new(1)?, &mut rng)?;
    let real_registration = Registration {
        expected_revision: None,
        pq_version: 1,
        lifecycle: Lifecycle::Enabled,
        bundle: identity.bundle.clone(),
        emergency: false,
    };
    let _: AdvertisedBundle = rest_client.http_form("PUT", "/user/pq-keys", &real_registration)?;
    eprintln!("[load-harness] one real registration succeeded; starting the sustained flood");

    // A deliberately stale expected_revision: every subsequent attempt is
    // a guaranteed, cheap-to-reject CAS conflict at the real write
    // endpoint -- real write *attempts*, most of which must be rejected
    // cleanly and quickly, exactly what design case 14 measures.
    let flood_registration = Registration {
        expected_revision: Some(Number::new(999_999)?),
        ..real_registration
    };

    let attempted = Arc::new(AtomicU64::new(0));
    let succeeded = Arc::new(AtomicU64::new(0));
    let rejected = Arc::new(AtomicU64::new(0));
    let errored = Arc::new(AtomicU64::new(0));
    let start_barrier = Arc::new(Barrier::new(threads as usize + 1));

    let per_thread_target = (target_per_second / threads.max(1)).max(1);
    let interval = Duration::from_secs_f64(1.0 / per_thread_target as f64);

    let mut handles = Vec::new();
    for _ in 0..threads {
        let server = config.server.clone();
        let body = flood_registration.clone();
        let attempted = attempted.clone();
        let succeeded = succeeded.clone();
        let rejected = rejected.clone();
        let errored = errored.clone();
        let start_barrier = start_barrier.clone();
        handles.push(std::thread::spawn(move || {
            let rest_client = RestClient::new(&server);
            start_barrier.wait();
            let deadline = Instant::now() + Duration::from_secs(duration_secs);
            let mut next_tick = Instant::now();
            while Instant::now() < deadline {
                attempted.fetch_add(1, Ordering::Relaxed);
                match rest_client.http_form::<_, AdvertisedBundle>("PUT", "/user/pq-keys", &body) {
                    Ok(_) => {
                        succeeded.fetch_add(1, Ordering::Relaxed);
                    },
                    Err(e) if e.has_status_of(409) => {
                        rejected.fetch_add(1, Ordering::Relaxed);
                    },
                    Err(_) => {
                        errored.fetch_add(1, Ordering::Relaxed);
                    },
                }
                next_tick += interval;
                let now = Instant::now();
                if next_tick > now {
                    std::thread::sleep(next_tick - now);
                }
            }
        }));
    }

    start_barrier.wait();
    let flood_start = Instant::now();
    for handle in handles {
        let _ = handle.join();
    }
    let elapsed = flood_start.elapsed();

    let attempted = attempted.load(Ordering::Relaxed);
    let succeeded = succeeded.load(Ordering::Relaxed);
    let rejected = rejected.load(Ordering::Relaxed);
    let errored = errored.load(Ordering::Relaxed);
    println!(
        "elapsed_secs={:.2} attempted={} succeeded={} rejected_409={} errored={} achieved_per_second={:.1}",
        elapsed.as_secs_f64(),
        attempted,
        succeeded,
        rejected,
        errored,
        attempted as f64 / elapsed.as_secs_f64()
    );

    Ok(())
}
