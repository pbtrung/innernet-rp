#[path = "../../tests/unit/support.rs"]
mod support;

use innernet_pq::protocol::{Decision, Kind, Number, Phase};
use support::*;

#[test]
fn clocks_fault_boundaries_and_non_consuming_delivery() {
    let mut clock = Clock::default();
    clock.advance(600);
    clock.expiry = 1; // Wall-clock correction never changes local scheduling.
    assert_eq!(clock.monotonic, 600);
    let mut storage = Storage {
        durable: 0,
        fault: Fault::Before,
    };
    assert!(storage.write(&1).is_err());
    assert_eq!(storage.restart(), 0);
    storage.fault = Fault::After;
    assert!(storage.write(&2).is_err());
    assert_eq!(storage.restart(), 2);
    storage.fault = Fault::None;
    storage.write(&3).unwrap();
    let mut transport = Transport::default();
    assert!(transport.send(1, Fault::Before).is_err());
    assert!(transport.fetch().is_empty());
    assert!(transport.send(2, Fault::After).is_err());
    assert_eq!(transport.fetch(), vec![2]);
    assert_eq!(transport.fetch(), vec![2]);
    transport.send(2, Fault::None).unwrap();
    assert_eq!(transport.fetch(), vec![2, 2]);
}

#[test]
fn stale_handshake_never_opens_recreated_peer() {
    let mut kernel = Kernel {
        gated: true,
        ..Default::default()
    };
    kernel.replace();
    kernel.handshake_generation = Some(1);
    kernel.replace();
    assert!(kernel.confirm(1).is_err());
    assert!(kernel.confirm(2).is_err());
    assert!(kernel.gated);
    kernel.handshake_generation = Some(2);
    kernel.confirm(2).unwrap();
    assert!(!kernel.gated);
}

#[test]
fn durable_receipts_and_replay_high_water_model() {
    let mut storage = Storage {
        durable: (Number::new(1).unwrap(), Decision::default()),
        fault: Fault::None,
    };
    let mut current = storage.restart();
    current.1.advance(Kind::Ready, false).unwrap();
    storage.write(&current).unwrap();
    current.1.advance(Kind::Commit, true).unwrap();
    storage.fault = Fault::After;
    assert!(storage.write(&current).is_err());
    let (high_water, mut decision) = storage.restart();
    decision.expire();
    assert_eq!(decision.phase, Phase::Committed);
    assert!(decision.advance(Kind::Abort, true).is_err());
    assert_eq!(high_water.get(), 1);
    assert_eq!(high_water.next().unwrap().get(), 2);
}
