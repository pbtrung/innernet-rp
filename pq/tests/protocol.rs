use innernet_pq::{
    Error,
    crypto::{self, Random, Secret, SystemRandom},
    protocol::*,
};

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!("../../tests/fixtures/protocol-v1.json")).unwrap()
}
fn transcript() -> Transcript {
    serde_json::from_value(fixtures()["transcript"].clone()).unwrap()
}
fn fixed_candidate() -> crypto::Candidate {
    crypto::derive(
        &Secret::from_bytes(std::array::from_fn(|i| i as u8)),
        &Secret::from_bytes(std::array::from_fn(|i| i as u8)),
        &Secret::from_bytes([0; 32]),
        &transcript().encode(),
    )
    .unwrap()
}

#[test]
fn independently_encoded_bundles_transcript_and_combiner() {
    let fixtures = fixtures();
    let t = transcript();
    t.validate().unwrap();
    assert_eq!(t.initiator.encode().len(), 1747);
    assert_eq!(hex(&t.initiator.encode()), fixtures["bundle_i_hex"]);
    assert_eq!(hex(&t.responder.encode()), fixtures["bundle_r_hex"]);
    assert_eq!(hex(&t.encode()), fixtures["transcript_hex"]);
    assert_eq!(
        hex(&crypto::hash(&t.encode()).unwrap()),
        fixtures["transcript_hash_hex"]
    );
    let c = fixed_candidate();
    assert_eq!(hex(c.psk.0.as_slice()), fixtures["psk_hex"]);
    assert_eq!(
        hex(c.initiator_confirmation.0.as_slice()),
        fixtures["kc_i_hex"]
    );
    assert_eq!(
        hex(c.responder_confirmation.0.as_slice()),
        fixtures["kc_r_hex"]
    );
    assert!(!c.psk.same(&c.initiator_confirmation));
    assert!(!c.initiator_confirmation.same(&c.responder_confirmation));
}

#[test]
fn every_message_matches_independent_rfc6979_signature_and_envelope() {
    let t = transcript();
    let candidate = fixed_candidate();
    for fixture in fixtures()["messages"].as_array().unwrap() {
        let bytes = serde_json::to_vec(&fixture["message"]).unwrap();
        assert!(bytes.len() <= REQUEST_LIMIT);
        let expected = parse_message(&bytes).unwrap();
        let mut scalar = [0; 66];
        scalar[65] = (expected.sender_id.get() - 1) as u8;
        let actual = Message::signed(
            &t,
            Kind::try_from(expected.message_type).unwrap(),
            expected.sender_id,
            &candidate,
            &Secret::from_bytes(scalar),
        )
        .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(hex(&actual.envelope()), fixture["envelope_hex"]);
        actual.authenticate(&t).unwrap();
        actual.confirm(&candidate).unwrap();
    }
}

#[test]
fn every_bound_field_is_authenticated() {
    let original = fixtures()["messages"][0]["message"].clone();
    for field in original.as_object().unwrap().keys() {
        let mut changed = original.clone();
        let value = changed.get_mut(field).unwrap();
        *value = match value {
            serde_json::Value::String(s) => {
                let mut bytes = s.as_bytes().to_vec();
                bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
                serde_json::Value::String(String::from_utf8(bytes).unwrap())
            },
            serde_json::Value::Number(n) => serde_json::json!(n.as_u64().unwrap() + 1),
            _ => unreachable!(),
        };
        let parsed = parse_message(&serde_json::to_vec(&changed).unwrap());
        assert!(
            parsed.and_then(|m| m.authenticate(&transcript())).is_err(),
            "accepted tampered {field}"
        );
    }
}

#[test]
fn canonical_json_and_exact_body_boundaries() {
    let original = serde_json::to_string(&fixtures()["messages"][0]["message"]).unwrap();
    let mut at_limit = original.as_bytes().to_vec();
    at_limit.resize(REQUEST_LIMIT, b' ');
    assert!(parse_message(&at_limit).is_ok());
    at_limit.push(b' ');
    assert!(parse_message(&at_limit).is_err());
    for bad in [
        format!("{original}{{}}"),
        original.replacen('{', "{\"version\":1,", 1),
        original.replacen('{', "{\"unknown\":true,", 1),
        original.replace("\"sequence\":\"1\"", "\"sequence\":1"),
    ] {
        assert!(parse_message(bad.as_bytes()).is_err());
    }
    for value in [
        "\"0\"",
        "\"01\"",
        "\"+1\"",
        "\"-1\"",
        "1",
        "\"9223372036854775808\"",
        "\" 1\"",
    ] {
        assert!(serde_json::from_str::<Number>(value).is_err());
    }
    for value in [1, (1 << 53) - 1, 1 << 53, (1 << 53) + 1, i64::MAX as u64] {
        let n = Number::new(value).unwrap();
        assert_eq!(
            serde_json::from_str::<Number>(&serde_json::to_string(&n).unwrap()).unwrap(),
            n
        );
    }
    assert!(Number::new(i64::MAX as u64).unwrap().next().is_err());
    for value in ["\"AQ\"", "\"AR==\"", "\"AQ==\\n\"", "\"_w==\""] {
        assert!(serde_json::from_str::<Binary<1>>(value).is_err());
    }
    let mut null = fixtures()["messages"][1]["message"].clone();
    null["ciphertext"] = serde_json::Value::Null;
    assert!(parse_message(&serde_json::to_vec(&null).unwrap()).is_err());
}

#[test]
fn raw_and_base64_size_contracts() {
    let t = transcript();
    assert_eq!(
        serde_json::to_string(&t.initiator.pq_kem_public_key)
            .unwrap()
            .len()
            - 2,
        2092
    );
    assert_eq!(
        serde_json::to_string(&t.ciphertext).unwrap().len() - 2,
        2168
    );
    let key_total = [
        serde_json::to_string(&t.initiator.pq_kem_public_key).unwrap(),
        serde_json::to_string(&t.initiator.pq_x448_public_key).unwrap(),
        serde_json::to_string(&t.initiator.pq_sig_public_key).unwrap(),
    ]
    .iter()
    .map(|s| s.len() - 2)
    .sum::<usize>();
    assert_eq!(key_total, 2260);
    assert!(serde_json::to_vec(&t.initiator).unwrap().len() < REQUEST_LIMIT);
}

#[test]
fn randomized_kem_agreement_and_implicit_rejection() {
    let (public, private) = crypto::hybrid_keypair(&mut SystemRandom).unwrap();
    assert_eq!(public, crypto::hybrid_public(&private).unwrap());
    let (_, wrong_private) = crypto::hybrid_keypair(&mut SystemRandom).unwrap();
    let (ct, shared) = crypto::encapsulate(&public).unwrap();
    let (next_ct, next_shared) = crypto::encapsulate(&public).unwrap();
    assert!(shared.same(&crypto::decapsulate(&ct, &private).unwrap()));
    assert!(!shared.same(&crypto::decapsulate(&ct, &wrong_private).unwrap()));
    assert!(ct != next_ct);
    assert_ne!(
        ct[1568..],
        next_ct[1568..],
        "each encapsulation has a fresh ephemeral X448 public key"
    );
    assert!(!shared.same(&next_shared));
    // No internal reject flag is exposed; the directional tag rejects wrong keys.
    let absent = Secret::from_bytes([0; 32]);
    let correct = crypto::derive(
        &shared.kem,
        &shared.x448,
        &absent,
        b"implicit rejection test",
    )
    .unwrap();
    let wrong = crypto::decapsulate(&ct, &wrong_private).unwrap();
    let rejected =
        crypto::derive(&wrong.kem, &wrong.x448, &absent, b"implicit rejection test").unwrap();
    assert_ne!(
        crypto::tag(&correct.initiator_confirmation, b"message").unwrap(),
        crypto::tag(&rejected.initiator_confirmation, b"message").unwrap()
    );
    let mut malformed = public;
    malformed.kem[..3].copy_from_slice(&[0xff; 3]);
    assert!(crypto::encapsulate(&malformed).is_err());
}

#[test]
fn x448_agreement_and_all_zero_rejection() {
    let (mut public, private) = crypto::hybrid_keypair(&mut SystemRandom).unwrap();
    let (mut ciphertext, shared) = crypto::encapsulate(&public).unwrap();
    assert!(shared.same(&crypto::decapsulate(&ciphertext, &private).unwrap()));
    ciphertext[1568..].fill(0);
    assert!(crypto::decapsulate(&ciphertext, &private).is_err());
    public.x448.fill(0);
    assert!(crypto::encapsulate(&public).is_err());
    for point in [[0; 56], std::array::from_fn(|i| u8::from(i == 0))] {
        assert!(crypto::validate_x448(&point).is_err());
        let mut t = transcript();
        t.responder.pq_x448_public_key = Binary(point);
        assert!(t.validate().is_err());
        let mut t = transcript();
        t.ciphertext.0[1568..].copy_from_slice(&point);
        assert!(t.validate().is_err());
    }
    let mut old_proposal = fixtures()["messages"][0]["message"].clone();
    old_proposal["ciphertext"] = serde_json::to_value(Binary([5; 1568])).unwrap();
    assert!(parse_message(&serde_json::to_vec(&old_proposal).unwrap()).is_err());
}

#[test]
fn signing_checks_points_scalars_low_s_and_message_binding() {
    let (public, private) = crypto::signing_keypair(&mut SystemRandom).unwrap();
    let signature = crypto::sign(&private, b"sample").unwrap();
    assert_eq!(signature, crypto::sign(&private, b"sample").unwrap());
    crypto::verify(&public, &signature, b"sample").unwrap();
    // n-s verifies mathematically, but protocol v1 forbids high-S encoding.
    assert_eq!(signature[66], 0);
    let order = "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409";
    let mut high_s = signature;
    let mut borrow = 0i16;
    for i in (0..66).rev() {
        let n = u8::from_str_radix(&order[i * 2..i * 2 + 2], 16).unwrap();
        let value = i16::from(n) - i16::from(signature[66 + i]) - borrow;
        high_s[66 + i] = value as u8;
        borrow = i16::from(value < 0);
    }
    assert!(crypto::verify(&public, &high_s, b"sample").is_err());
    assert!(crypto::verify(&public, &signature, b"changed").is_err());
    assert!(crypto::verify(&public, &[0; 132], b"sample").is_err());
    assert!(crypto::verify(&public, &[255; 132], b"sample").is_err());
    assert!(crypto::validate_signing(&[0; 67]).is_err());
    assert!(crypto::signing_public(&Secret::from_bytes([0; 66])).is_err());
    assert!(crypto::signing_public(&Secret::from_bytes([255; 66])).is_err());
    let mut malformed = public;
    malformed[0] = 4;
    assert!(crypto::validate_signing(&malformed).is_err());
    let mut outside_field = [255; 67];
    outside_field[0] = 2;
    assert!(crypto::validate_signing(&outside_field).is_err());
}

#[test]
fn each_combiner_input_changes_keys_and_confirmation() {
    let a = Secret::from_bytes([1; 32]);
    let b = Secret::from_bytes([2; 32]);
    let x = Secret::from_bytes([3; 56]);
    let y = Secret::from_bytes([4; 56]);
    let absent = Secret::from_bytes([0; 32]);
    let original = crypto::derive(&a, &x, &absent, b"context").unwrap();
    for changed in [
        crypto::derive(&b, &x, &absent, b"context").unwrap(),
        crypto::derive(&a, &y, &absent, b"context").unwrap(),
        crypto::derive(&a, &x, &b, b"context").unwrap(),
        crypto::derive(&a, &x, &absent, b"changed").unwrap(),
    ] {
        assert!(!original.psk.same(&changed.psk));
        assert_ne!(
            crypto::tag(&original.initiator_confirmation, b"message").unwrap(),
            crypto::tag(&changed.initiator_confirmation, b"message").unwrap()
        );
    }
}

#[test]
fn randomness_failure_never_returns_partial_identity() {
    struct Fail;
    impl Random for Fail {
        fn fill(&mut self, _: &mut [u8]) -> innernet_pq::Result<()> {
            Err(Error::Random)
        }
    }
    assert!(crypto::hybrid_keypair(&mut Fail).is_err());
    assert!(crypto::signing_keypair(&mut Fail).is_err());
    assert!(crypto::random::<56>(&mut Fail).is_err());
}

#[test]
fn state_model_requires_commit_and_responder_first() {
    let mut state = Decision::default();
    assert!(state.advance(Kind::Installed, false).is_err());
    assert!(state.advance(Kind::Commit, true).is_err());
    assert!(state.advance(Kind::Ready, true).is_err());
    state.advance(Kind::Ready, false).unwrap();
    state.advance(Kind::Commit, true).unwrap();
    state.expire();
    assert_eq!(state.phase, Phase::Committed);
    assert!(state.advance(Kind::Abort, true).is_err());
    assert!(state.advance(Kind::Installed, true).is_err());
    assert!(state.advance(Kind::Confirmed, false).is_err());
    state.advance(Kind::Installed, false).unwrap();
    state.advance(Kind::Installed, true).unwrap();
    state.advance(Kind::Confirmed, true).unwrap();
    state.advance(Kind::Confirmed, false).unwrap();
    assert_eq!(state.phase, Phase::Complete);
}

#[test]
fn expiry_wins_before_commit_and_not_after() {
    for phase in [Phase::Proposed, Phase::Ready] {
        let mut state = Decision {
            phase,
            ..Default::default()
        };
        state.expire();
        assert_eq!(state.phase, Phase::Aborted);
        assert!(state.advance(Kind::Commit, true).is_err());
    }
}
