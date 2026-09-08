#[test]
fn coverage_manifest_has_all_cases_and_resolves_unit_test_names() {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/coverage.json")).unwrap();
    let cases = manifest["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 18);
    let source = [
        include_str!("protocol.rs"),
        include_str!("harness.rs"),
        include_str!("native_interop.rs"),
        include_str!("store.rs"),
        include_str!("schedule.rs"),
        include_str!("../src/state.rs"),
        include_str!("../src/engine.rs"),
        include_str!("../../server/src/api/pq_tests.rs"),
        include_str!("../../server/src/db/pq_migration_tests.rs"),
        include_str!("../../server/src/management.rs"),
        include_str!("../../server/src/gate.rs"),
        include_str!("../../client-core/src/management.rs"),
        include_str!("../../client-core/tests/pq_exchange.rs"),
        include_str!("../../shared/src/pq.rs"),
    ]
    .concat();
    for (index, case) in cases.iter().enumerate() {
        assert_eq!(case["design_case"].as_u64(), Some(index as u64 + 1));
        for suite in ["unit", "integration"] {
            for test in case[suite].as_array().unwrap() {
                let name = test.as_str().unwrap();
                assert!(
                    source.contains(&format!("fn {name}(")),
                    "unresolved test {name}"
                );
            }
        }
    }
}
