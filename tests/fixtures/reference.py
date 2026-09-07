#!/usr/bin/env python3
"""Independent protocol-vector oracle; TEST DATA ONLY, never use these keys.

Uses Python's standard hash/HMAC library and straightforward public test-scalar
arithmetic, not the Rust encoder or leancrypto. Deliberately not constant-time:
this is an offline oracle for published fixed vectors, not production crypto.
Writes JSON to stdout; with --check PATH compares with the committed fixture.
"""
import base64
import hashlib
import hmac
import json
import sys

P = 2**521 - 1
N = int("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16)
G = (
    int("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", 16),
    int("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", 16),
)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y + v) % P == 0:
        return None
    slope = ((3*x*x - 3) * pow(2*y, -1, P) if a == b
             else (v-y) * pow(u-x, -1, P)) % P
    r = (slope*slope - x-u) % P
    return r, (slope*(x-r)-y) % P


def mul(k):
    result, point = None, G
    while k:
        if k & 1:
            result = add(result, point)
        point = add(point, point)
        k >>= 1
    return result


def public(d):
    x, y = mul(d)
    return bytes([2 + (y & 1)]) + x.to_bytes(66, "big")


def sign(d, message):
    digest = hashlib.sha512(message).digest()
    z = int.from_bytes(digest, "big")
    bx = d.to_bytes(66, "big") + (z % N).to_bytes(66, "big")
    v, k = b"\x01" * 64, b"\0" * 64
    mac = lambda key, value: hmac.digest(key, value, "sha512")
    k = mac(k, v + b"\0" + bx)
    v = mac(k, v)
    k = mac(k, v + b"\x01" + bx)
    v = mac(k, v)
    while True:
        v = mac(k, v)
        t = v
        v = mac(k, v)
        t += v
        nonce = int.from_bytes(t, "big") >> (len(t)*8 - 521)
        if 1 <= nonce < N:
            r = mul(nonce)[0] % N
            s = (pow(nonce, -1, N) * (z + r*d)) % N
            if r and s:
                return r.to_bytes(66, "big") + min(s, N-s).to_bytes(66, "big")
        k = mac(k, v + b"\0")
        v = mac(k, v)


def b64(value):
    return base64.b64encode(value).decode("ascii")


def u64(value):
    return value.to_bytes(8, "big")


def bundle(side):
    values = {
        "bundle_id": bytes([side])*16,
        "bundle_revision": str(side),
        "wg_public_key": bytes([side+30])*32,
        "pq_kem_public_key": bytes(1536) + bytes([side])*32,
        "pq_x448_public_key": bytes([side])*56,
        "pq_sig_public_key": public(side),
    }
    encoded = (values["bundle_id"] + u64(side) + values["wg_public_key"]
               + values["pq_kem_public_key"] + values["pq_x448_public_key"]
               + values["pq_sig_public_key"])
    return {key: b64(value) if isinstance(value, bytes) else value
            for key, value in values.items()}, encoded


def vectors():
    first, b_i = bundle(1)
    second, b_r = bundle(2)
    # Hybrid ciphertext: ML-KEM component followed by ephemeral X448 public key.
    network, exchange, operator = bytes([3])*16, bytes([4])*16, bytes(16)
    ciphertext = bytes([5])*1568 + bytes([6])*56
    transcript = (b"innernet pq-psk v1 transcript" + b"\1" + network
                  + u64(2) + u64(3) + b_i + b_r + u64(1) + exchange + operator + ciphertext)
    hashed = hashlib.sha3_256(transcript).digest()
    ikm = bytes(range(32)) + bytes(range(56)) + bytes(32)
    prk = hmac.digest(hashed, ikm, "sha3_256")
    expand = lambda label: hmac.digest(prk, label + hashed + b"\1", "sha3_256")
    psk, kc_i, kc_r = [expand(b"innernet pq-psk v1 " + suffix)
                       for suffix in (b"psk", b"confirm i", b"confirm r")]
    messages = []
    for code, sender in [(1, 2), (2, 3), (3, 2), (4, 3), (4, 2), (5, 2), (5, 3), (6, 2)]:
        envelope = (b"innernet pq-psk v1 message" + b"\1" + network + u64(2) + u64(3)
                    + bytes([1])*16 + bytes([2])*16 + u64(1) + exchange + hashed + u64(sender) + bytes([code]))
        tag = hmac.digest(kc_i if sender == 2 else kc_r, envelope, "sha3_256")
        message = dict(version=1, network_id=b64(network), initiator_id="2", responder_id="3",
                       initiator_bundle_id=b64(bytes([1])*16), responder_bundle_id=b64(bytes([2])*16),
                       sequence="1", exchange_id=b64(exchange), transcript_hash=b64(hashed),
                       sender_id=str(sender), message_type=code, tag=b64(tag),
                       signature=b64(sign(sender-1, envelope + tag)))
        if code == 1:
            message.update(ciphertext=b64(ciphertext), operator_psk_id=b64(operator))
        messages.append(dict(message=message, envelope_hex=envelope.hex()))
    return dict(test_only=True, source="Independent Python reference, fixed public test scalars 1/2",
                transcript=dict(network_id=b64(network), initiator_id="2", responder_id="3",
                                initiator=first, responder=second, sequence="1", exchange_id=b64(exchange),
                                operator_psk_id=b64(operator), ciphertext=b64(ciphertext)),
                bundle_i_hex=b_i.hex(), bundle_r_hex=b_r.hex(), transcript_hex=transcript.hex(),
                transcript_hash_hex=hashed.hex(), psk_hex=psk.hex(), kc_i_hex=kc_i.hex(), kc_r_hex=kc_r.hex(),
                messages=messages)


if __name__ == "__main__":
    result = vectors()
    if len(sys.argv) == 3 and sys.argv[1] == "--check":
        with open(sys.argv[2], encoding="utf-8") as fixture:
            if json.load(fixture) != result:
                raise SystemExit("protocol fixture disagrees with independent reference")
        print("Independent protocol reference: all vectors match")
    elif len(sys.argv) == 1:
        print(json.dumps(result, indent=2))
    else:
        raise SystemExit("usage: reference.py [--check PATH]")
