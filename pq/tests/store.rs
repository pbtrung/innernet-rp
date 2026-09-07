#![cfg(unix)]
use innernet_pq::store::{Store, StoreError};

#[test]
fn private_storage_excludes_other_processes() {
    const CHILD: &str = "INNERNET_TEST_PRIVATE_STORE_CHILD";
    if let Some(path) = std::env::var_os(CHILD) {
        assert!(matches!(
            Store::open(std::path::Path::new(&path), false),
            Err(StoreError::Busy)
        ));
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private");
    let mut owner = Store::open(&path, true).unwrap();
    owner.save(&1u64).unwrap();
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "private_storage_excludes_other_processes"])
        .env(CHILD, &path)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn private_storage_never_downgrades_newer_or_unexpected_snapshots() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private");
    let mut owner = Store::open(&path, true).unwrap();
    owner.save(&1u64).unwrap();
    let file = path.join("state.json");
    let bytes = std::fs::read(&file).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["version"] = 2.into();
    std::fs::write(&file, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(matches!(owner.load::<u64>(), Err(StoreError::Newer)));
    assert!(matches!(owner.save(&2u64), Err(StoreError::Newer)));
    value["version"] = 1.into();
    value["value"] = 9.into();
    let changed = serde_json::to_vec(&value).unwrap();
    std::fs::write(&file, &changed).unwrap();
    assert!(matches!(owner.save(&2u64), Err(StoreError::Conflict)));
    assert_eq!(std::fs::read(&file).unwrap(), changed);
    std::fs::write(&file, b"broken partial state").unwrap();
    assert!(matches!(owner.load::<u64>(), Err(StoreError::Corrupt)));
}
