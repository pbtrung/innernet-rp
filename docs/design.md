# Design: Post-quantum WireGuard via peer-to-peer ML-KEM exchange

Status: draft
Related: [milestones.md](milestones.md)

## 1. Motivation

innernet peers connect over WireGuard, whose handshake authenticates and
derives keys using Curve25519 (X25519). That is not post-quantum secure:
traffic recorded today could be decrypted later by an adversary with a
cryptographically relevant quantum computer ("harvest now, decrypt later").

This doc proposes hardening every WireGuard link against that threat by
periodically deriving a **preshared key (PSK)** from a genuine post-quantum
key encapsulation mechanism (KEM), and feeding it into WireGuard exactly the
way any operator-supplied PSK works today. This does not replace the
WireGuard handshake — it strengthens it: WireGuard's `Noise_IKpsk2` pattern
mixes the PSK into the final session key, so the combination is
cryptographically no less secure than WireGuard on its own, and enabling it
can only help.

The distinguishing design choice here is **how** the two sides of a link
exchange the KEM material: directly, peer-to-peer, using the *existing*
coordination-server channel every peer already talks to for peer discovery —
not a new, separately-exposed network service. The server's role stays
exactly what it already is for WireGuard public keys and endpoints: a
directory peers push to and pull from. It never sees a private key or a
derived secret, only opaque ciphertext blobs it relays.

## 2. Background: ML-KEM and why a relay, not a listener

- **ML-KEM** (FIPS 203, standardized 2024, formerly known as Kyber) is a
  NIST-standardized post-quantum KEM. A KEM has three operations: `KeyGen()`
  → `(public_key, secret_key)`; `Encapsulate(public_key)` → `(ciphertext,
  shared_secret)`; `Decapsulate(secret_key, ciphertext)` → `shared_secret`
  (the same value the encapsulating side produced). Critically, this is a
  **one-shot** operation, not an interactive multi-round-trip protocol — the
  encapsulating side needs nothing from the other side except its long-lived
  public key, which it can fetch once and cache.
- ML-KEM-768's sizes are small enough to travel as ordinary API payloads:
  public key ~1184 bytes, ciphertext ~1088 bytes, both comfortably under a
  kilobyte and a half base64-encoded. This is the key enabling fact for this
  design: it means the public key can be *just another field* on a peer's
  existing record, and a ciphertext can be *just another small object* the
  coordination server temporarily stores and forwards — no separate listener,
  no separate wire protocol, no new exposed port.
- Because encapsulation is one-shot and asynchronous (the encapsulating side
  doesn't need the other side to be online at that exact instant — it just
  needs the recipient's public key, which is already cached), the natural
  transport for the ciphertext is the *same* request/response channel a peer
  already uses to fetch its peer list: drop the ciphertext off, the recipient
  picks it up on its next regular poll.
- This deliberately avoids running any new always-on network service per
  peer. Every additional exposed listener is additional attack surface (an
  unauthenticated flood against it, a parser bug in a new wire format, a
  port an operator has to remember to firewall) — see §6 for why this
  matters more than it might first appear.

## 3. Relevant existing innernet architecture

(For readers unfamiliar with the codebase; skip to §5 if not.)

- **Coordination server, not a data-plane relay.** The server holds a
  SQLite-backed peer database (`server/src/db/`) — each peer's WireGuard
  public key, IP, CIDR membership, and endpoint. It never carries actual
  VPN traffic; peers fetch each other's info and then talk to each other
  directly over WireGuard. This design keeps that property: the mailbox
  described below stores tiny ciphertext blobs, never tunnel traffic.
- **Peer visibility already follows CIDR scoping.** A peer only ever learns
  about the peers it's authorized to see, enforced server-side per existing
  CIDR/authorization rules. Any new per-peer field added to the peer record
  inherits this scoping for free — nothing new to re-implement.
- **The bulk state fetch.** Clients periodically call `GET /v1/user/state`
  (driven by `innernet up --daemon --interval <seconds>`, default 60s) to
  get their current peer list and apply it to the local WireGuard interface.
  The server also runs its own equivalent sync loop for its own
  coordination-API WireGuard link (see §5.10). This existing poll loop is
  the natural place to also pick up and process pending KEM material —
  no new polling loop needs to be invented.
- **PSK application is already a solved, separate concern.** Applying a PSK
  to a running WireGuard interface is a small, non-disruptive
  `PeerConfigBuilder::set_preshared_key` + `DeviceUpdate::apply` call —
  wireguard-control merges peer settings onto the existing peer rather than
  tearing down the tunnel. Nothing about this design changes that mechanism;
  it only changes how the PSK value gets derived.
- **Feature flags and backward compatibility.** `ServerCapabilities`
  (`shared/src/types.rs`) is how the server already advertises optional
  features to clients, and `PeerContents` fields already use
  `#[serde(default)]` so old and new client/server combinations
  interoperate without a hard cutover. The schema changes below follow
  that exact pattern.

## 4. Non-goals

- Not building general-purpose NAT traversal for the exchange — it reuses
  the coordination server's already-authenticated channel, which every peer
  already reaches by construction (it has to, to get its peer list at all).
- Not attempting to hide metadata (who is exchanging keys with whom) from
  the coordination server — it already knows the full peer graph and CIDR
  membership; this adds nothing new to that trust boundary.
- Not building a general pub/sub or messaging system. The mailbox is
  intentionally narrow: one pending ciphertext per ordered peer pair, with a
  short TTL — not a general delivery mechanism for arbitrary payloads.

## 5. Proposed design

### 5.1 Data model & schema changes

- Add a nullable `pq_kem_public_key` column to the `peers` table
  (`server/src/db/peer.rs`), threaded through `create`/`update`/`from_row`/
  `COLUMNS` — mirrors how the WireGuard public key column already works.
- Add the field to `PeerContents` with `#[serde(default)]`
  (`shared/src/types.rs`), so old clients/servers round-trip peer records
  without it.
- Add `pq_kem: bool` to `ServerCapabilities`, following the existing pattern
  for advertising optional features.
- New table, `pq_handshake_mailbox`: `(to_peer_id, from_peer_id, ciphertext,
  created_at)`, primary-keyed on `(to_peer_id, from_peer_id)` — at most one
  pending, undelivered ciphertext per ordered pair at a time. A fresh
  encapsulation overwrites any previous undelivered one for that pair rather
  than accumulating a backlog.

### 5.2 New server endpoints

- `PUT /v1/user/pq-handshake/{to_peer_id}` — upload a ciphertext addressed
  to another peer. Validates: payload size matches the expected ML-KEM-768
  ciphertext length exactly (reject anything else outright, same spirit as
  the existing candidate-endpoint size caps), `to_peer_id` must be a peer
  the caller is authorized to see (same CIDR check already applied to
  peer-list visibility).
- Delivery needs no separate `GET` endpoint: pending ciphertexts addressed
  to the requester are embedded directly in the existing `GET /v1/user/state`
  response (one extra optional field per peer entry the fetcher is
  authorized to see). The server deletes a mailbox row once served in a
  response — at-most-once delivery, no separate ack round trip.
- A short TTL (a small multiple of the fetch interval — e.g. 10 minutes)
  garbage-collects anything nobody ever picked up, so the table can't grow
  unbounded from peers that are offline or have since been removed.

### 5.3 Client: keypair lifecycle

- Generate an ML-KEM-768 keypair once per interface (on `install`/
  `redeem-invite`), store the secret key `0o600` under
  `<data_dir>/interfaces/<interface>/pq-kem/` — same permission discipline
  and directory shape as the existing WireGuard private key handling in
  `interface_config.rs`.
- Register the public key via a `RestClient` method
  (`client-core/src/rest_client.rs`) called once at install and re-checked
  (idempotently — only send if it doesn't already match what the server has
  on record) on every `up`, mirroring the existing idempotent-registration
  pattern already used elsewhere in this codebase for other per-peer fields.
- `innernet show`: display whether the local interface and each visible
  peer has advertised a PQ KEM public key.

### 5.4 Dial/listen tie-break for exchange initiation

Exactly one side of every peer pair must be the one to encapsulate first
(the "initiator" for that pair) — if both sides encapsulated independently
and applied their own locally-computed secret, they'd derive **two
different** values and the tunnel would silently fail to agree on a PSK,
with no visible error. Both sides need to reach the same
initiator/responder assignment without coordinating, so it's derived from
something both already know: peer ID.

- The coordinating server is always peer id 1 (the first peer any network
  has). It's special-cased to always be the **responder**, never the
  initiator: it's the side an operator can reliably keep online 24/7, while
  any other peer may be offline, asleep, or behind a NAT with no stable
  reachability — none of which matters here, since initiation only requires
  the *coordination server* to be reachable (which every peer already
  assumes), not the other peer directly.
- For a pair where neither side is the server, there's no such asymmetry to
  exploit, so it falls back to an arbitrary but deterministic tie-break: the
  lower peer ID initiates.

### 5.5 Peer-to-peer exchange protocol

Per ordered pair `(initiator, responder)` decided by §5.4:

1. The initiator fetches the responder's `pq_kem_public_key` (already
   present in its regular peer-list fetch — no extra round trip).
2. The initiator calls `Encapsulate(responder_public_key)` locally, getting
   `(ciphertext, shared_secret_a)`.
3. The initiator uploads only the ciphertext via
   `PUT /v1/user/pq-handshake/{responder_id}`. The shared secret and the
   secret key never leave the initiator's machine.
4. On the responder's next regular state fetch, the pending ciphertext for
   this pair is included in the response. The responder calls
   `Decapsulate(own_secret_key, ciphertext)`, recovering
   `shared_secret_b == shared_secret_a`.
5. Both sides independently derive a WireGuard-compatible 32-byte PSK from
   the shared secret via HKDF (see §5.7 for what else gets mixed in), and
   apply it to that specific peer's WireGuard config
   (`PeerConfigBuilder::set_preshared_key` + `DeviceUpdate::apply`) —
   exactly as any other PSK update already works in this codebase.

### 5.6 Rotation cadence & confirmation

- There is no externally-imposed rekey timer to inherit — rotation cadence
  is a parameter of *this* implementation, tied directly to the existing
  `up --daemon --interval` loop (client) and the server's own periodic sync
  task. A reasonable default is every few polling cycles, not every single
  one, to bound the steady-state ciphertext-upload traffic.
- **Confirmation reuses WireGuard's own handshake, rather than building a
  bespoke acknowledgment protocol.** After applying a newly-derived PSK,
  nothing needs to explicitly verify the two sides agree — if they don't,
  WireGuard's own `Noise_IKpsk2` handshake (which mixes the PSK in) simply
  fails to complete for that peer, exactly like an outright key mismatch
  today. On failure, keep the previous working PSK in place until the next
  rotation succeeds, rather than clearing it — the same "never leave a link
  with no PSK at all due to a single failed cycle" principle applied
  everywhere else PSKs are handled in this codebase.

### 5.7 Hybrid classical+PQ secret combiner

Relying on a single post-quantum algorithm family means a future
cryptanalytic break of that one algorithm compromises every derived PSK.
Standard practice (matching TLS 1.3's `X25519MLKEM768` and OpenSSH's
default post-quantum key exchange) is to combine an ML-KEM shared secret
with an independent classical ECDH shared secret via a KDF, so the result
stays secure as long as *either* half remains unbroken:

- Generate a dedicated X25519 keypair per interface alongside the ML-KEM
  one (not the WireGuard static key itself — keeping these separate avoids
  any cross-protocol key-reuse concerns).
- Perform an ordinary X25519 ECDH alongside the ML-KEM encapsulation in the
  same round described in §5.5.
- `psk = HKDF(ikm = ml_kem_shared_secret || x25519_shared_secret, info =
  "innernet pq-psk v1", length = 32)`.

### 5.8 Trust boundary for the relayed ciphertext

The coordination server relays the ciphertext but cannot read the shared
secret it encapsulates — it only ever handles opaque bytes. However, since
the server is also the source of truth for a peer's advertised
`pq_kem_public_key`, a compromised server could in principle substitute its
own keypair when asked "what is peer B's public key," letting it decrypt
what it thinks is peer A's message to B (a relay-level MITM). This is
**the same trust boundary the coordination server already has** for
WireGuard public key distribution — a compromised server can already
substitute a WireGuard public key and MITM the classical handshake today,
so this doesn't newly expand what a compromised server can do, only extends
an already-accepted trust assumption to one more field.

For deployments wanting a stronger guarantee that doesn't rely on trusting
the server for this, a future extension can have each side sign its
ciphertext (and the responder's public key it was encapsulated against)
with a dedicated per-peer Ed25519 identity key, letting the other side
verify the message actually came from who it claims — deferred as an
explicit future option (§8) rather than assumed as part of the baseline
design.

### 5.9 Mailbox lifecycle & cleanup

- At most one undelivered ciphertext per ordered pair (§5.1) bounds storage
  regardless of how many rotation cycles are missed.
- Delete-on-delivery (§5.2) means a healthy, regularly-polling fleet never
  accumulates backlog at all.
- The TTL-based sweep (§5.2) bounds storage from peers that go permanently
  offline or get removed before ever polling again.

### 5.10 Server as a mesh peer

The coordination server is itself a WireGuard peer (its own coordination-API
link), and participates in this scheme exactly like any other peer: it
generates its own ML-KEM/X25519 keypairs, advertises its public keys via its
own database row, and runs the same periodic sync task client interfaces
run, applying the resulting PSK to its own device — no special-casing beyond
the responder role already assigned to it in §5.4.

### 5.11 Permissive mode & mixed-fleet interop

Not every peer will have this enabled — a phone running a stock WireGuard
client, for instance, has no `pq_kem_public_key` to advertise at all. This
is handled the same way any other opt-in per-peer capability is in this
codebase: a peer that enables PQ hardening (`--enable-pq-psk`, say) can
additionally opt into `--pq-psk-permissive`, which falls back to a plain
WireGuard connection (no PSK) for any peer that hasn't advertised a
`pq_kem_public_key`, instead of treating it as unreachable. This is always a
per-operator, client-side choice — the server isn't in the data path and
can't force a peer to run this locally, only tell peers about each other.

### 5.12 Independent per-peer state, by construction

Because each peer pair's PSK is derived from a standalone, independent
KEM exchange — not a shared multi-peer process with one combined
configuration file — pausing, skipping, or backing off the rotation cadence
for one specific idle peer has **no effect on any other peer's exchange**.
This falls out of the architecture rather than needing to be specially
engineered: there is no shared daemon to restart, no combined config file
to regenerate, and no reason a per-peer idle-detection policy (e.g.
"don't bother rotating a peer with zero WireGuard traffic in the last N
minutes") would ever need to touch any other peer's state. Left as a
concrete feature for future work (§8), but worth calling out here as a
structural property this design has and a shared-process design would not.

## 6. Security considerations

- **No new exposed listener.** Every exchange happens over the same
  request/response channel already used for peer discovery, authenticated
  the same way (existing peer-key-based auth on the coordination API). There
  is no new UDP (or any other) port for an operator to open, firewall, or
  rate-limit, and therefore no new standalone flood/amplification/DoS
  surface distinct from what the coordination API already has to defend
  against.
- **Forward secrecy is a function of rotation cadence.** Each rotation
  produces an independent secret from a fresh encapsulation; compromising
  one derived PSK doesn't expose any other rotation's value (ML-KEM
  ciphertexts don't reveal the secret key, and each encapsulation is
  independently randomized).
- **Replay.** A captured, replayed ciphertext just re-derives the exact same
  secret the original exchange already produced — not a new one — so replay
  by itself doesn't help an attacker who doesn't already have the
  corresponding secret key. The mailbox's delete-on-delivery semantics
  additionally mean a legitimate replay opportunity (re-delivering the same
  ciphertext twice) shouldn't normally arise at all.
- **Server-compromise blast radius** is bounded to what §5.8 already
  describes: a compromised server can MITM the relay, matching its existing
  ability to MITM WireGuard peer identity distribution — not a new category
  of exposure introduced by this design.
- **Input validation on the mailbox endpoint** must reject anything that
  isn't exactly a well-formed ML-KEM-768 ciphertext-sized payload outright,
  the same discipline already applied to the existing candidate-endpoint
  validation, so a malformed upload can't be used to probe for parser bugs
  or store oversized garbage.

## 7. Alternatives considered

- **A dedicated always-on companion process with its own listening port**,
  running an independent PQ key-exchange protocol over the network directly
  between peers. Rejected as the default approach here specifically because
  it reintroduces exactly the operational costs this design avoids: a new
  exposed port per listening peer to firewall/rate-limit, a new standalone
  DoS surface, and — because such a daemon typically holds one combined
  config file for all of its peers rather than independent per-pair state —
  a change to any single peer's configuration typically forces a full
  process restart affecting every other peer's session simultaneously.
- **A large-public-key, code-based KEM** (multi-hundred-kilobyte to
  megabyte-scale public keys) as an additional hedge alongside a
  lattice-based KEM. Rejected for the default design: a key that large
  can't reasonably travel as an ordinary API field the way ML-KEM's ~1.2 KB
  key can, which is precisely the property this design depends on to avoid
  a separate distribution mechanism. The classical+ML-KEM hybrid in §5.7
  provides an algorithm-family hedge without that size cost.
- **A fully local, hash-ratcheted PSK schedule** (seed once via a trusted
  out-of-band channel, e.g. in person or via QR code, then have both sides
  independently derive every subsequent rotation via a one-way KDF, never
  transmitting new key material over the network again). Genuinely
  post-quantum secure in principle — a hash-based ratchet doesn't rely on
  a KEM at all — but rejected as the default: it has no way to
  automatically provision a newly-invited peer (there's no network-based
  bootstrap step at all, by design), and any missed rotation on either side
  permanently desynchronizes the two chains with no recovery mechanism
  short of re-seeding out-of-band again. Not a fit for a system built
  around automatic, network-driven peer provisioning.

## 8. Open questions / risks

- Exact rotation-interval default and whether it should be independently
  configurable from the general `up --daemon --interval`, or simply a fixed
  multiple of it.
- Whether the §5.8 signed-ciphertext hardening (removing the "trust the
  server for relay integrity" assumption) is worth building as part of the
  initial rollout, or genuinely deferrable given it doesn't expand the
  existing trust boundary.
- The exact idle-detection policy and threshold for the per-peer
  pause/resume property described in §5.12 — this design makes it possible
  cheaply, but the concrete heuristic (what counts as "idle," how quickly to
  resume once traffic returns, whether resumption should be eager or wait
  for the next natural rotation) is left unspecified here.
- Mailbox table growth under a large, mostly-online fleet with a short
  rotation interval — the TTL sweep bounds worst case, but the concrete
  interval/TTL defaults should be chosen with real fleet sizes in mind
  before this ships.
