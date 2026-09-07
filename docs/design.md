# Design: Post-quantum WireGuard PSKs via relayed ML-KEM exchange

Status: draft; protocol and implementation validation required before release
Related: [milestones.md](milestones.md)
Test execution plan: [testing.md](testing.md)

## 1. Motivation and security scope

WireGuard's classical elliptic-curve handshake does not protect recorded
traffic from a future cryptographically relevant quantum computer. A secret
32-byte preshared key (PSK), mixed into `Noise_IKpsk2`, can add protection
against that passive "harvest now, decrypt later" threat.

This design derives rotating PSKs for client-to-client data links using
ML-KEM-1024 and X448. Peers exchange public material through the existing
coordination API; no additional peer listener is required. The API server
is a trusted directory and relay, not a relay for application traffic.

Each client's coordination-server link is a deliberate exception: it uses
a separately provisioned random PSK, with administrative rotation over an
independent access path. It does not use mailbox-driven rotation, because
the mailbox must remain reachable when data-link PSKs are mismatched.
Section 5.10 defines provisioning, rotation, and recovery for this link.

Claims assume honest endpoints, a trusted directory, secure randomness, and
uncompromised long-term secrets. Mandatory P-521 signatures authenticate
messages relative to the directory's keys; they do not remove that trust
or provide post-quantum identity authentication. Static ML-KEM/X448 keys do
not give the PSK layer forward secrecy after long-term key compromise.
Rotation requires explicit durable protocol state beyond WireGuard itself.

Implementation proceeds by milestone; see [implementation.md](implementation.md)
for actual evidence. Existing innernet behavior alone does not implement this
proposal. The specification is implementation-language-independent.

## 2. Cryptographic building blocks and transport sizes

- **ML-KEM-1024** is the FIPS 203 Category 5 parameter set: public key and
  ciphertext are each 1568 bytes; the shared secret is 32 bytes. A single
  encapsulation is asynchronous, but reliable PSK activation requires the
  multi-message protocol in section 5.5.
- **X448** uses a dedicated recipient interface key and a fresh encapsulator
  ephemeral key through leancrypto's combined ML-KEM-1024/X448 API. Public
  keys and shared secrets are 56 bytes; its roughly
  224-bit classical security margin is distinct from ML-KEM's category.
- **HKDF-SHA3-256** combines secrets and authenticated context, deriving
  separate PSK and confirmation keys (section 5.7).
- **ECDSA P-521 with SHA-512** signs every exchange message. Public keys
  use 67-byte compressed SEC1 encoding; signatures use 132-byte raw `r || s`.
  Signing is mandatory in version 1, with no unsigned negotiation mode.

A 1568-byte field becomes **2092 bytes in padded base64**, exceeding both
2000 bytes and 2 KiB. The hybrid ciphertext is 1624 bytes (1568-byte ML-KEM
ciphertext followed by a 56-byte ephemeral X448 public key), or 2168 bytes
in base64. Hybrid ciphertext plus signature alone is 2344 base64 bytes;
all three public keys total 2260 base64 bytes. Actual requests also carry
identifiers, versions, confirmation tags, and JSON overhead (section 8).

Algorithm and validation references:
[FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf),
[RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html), and
[FIPS 186-5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf).

### 2.1 Libraries, storage, and packaging

Use leancrypto's `lc_kyber_x448_keypair`, `lc_kyber_x448_enc` and
`lc_kyber_x448_dec` APIs with `LC_KYBER_1024`, together with their checked
load/pointer/public-key recovery helpers. Export components explicitly; never
serialize library structs, enum tags, or padding. The combined KEM supplies
the 32-byte ML-KEM and 56-byte X448 shared secrets for section 5.7. Its optional
`*_kdf` KMAC variant is not used: retain transcript-bound HKDF-SHA3-256,
operator-PSK adoption, and directional confirmation keys. SHA3, HMAC, HKDF
and the seeded identity DRBG also use system leancrypto; OpenSSL supplies
P-521/SHA-512 signatures.

This hybrid API choice explicitly revises the pre-release M0 fixture format.
The full 1624-byte hybrid ciphertext is signed through the transcript hash;
the original standalone 1568-byte proposal is rejected. No released/activated
protocol is silently reinterpreted; M0 did not permit production activation.

Both crypto libraries and SQLite link against system-provided shared
libraries, with no vendored/bundled copies. Record exact tested package
versions in reproducible CI/build environments and declare minimum runtime
versions and ABI requirements. Package updates repeat relevant checks;
unpinned upstream branches are not the dependency policy. Algorithm
approval alone does not establish FIPS module validation.

SQLite gains three public-key fields, bundle metadata, and durable exchange
records (section 5.1). It holds no client-to-client PSKs or private keys.
Server-link PSKs are endpoint secrets stored separately with the server's
private configuration, as specified in section 5.10.

## 3. Existing architecture and integration boundaries

innernet distributes peer WireGuard keys, addresses, endpoints, and CIDR
visibility through a coordination API carried over WireGuard. Peers normally
fetch state every 60 seconds. Reuse that loop for delivery and reconciliation,
including when there is no application traffic. Poll and rotation timers
have separate meanings.

Explicitly enforce existing visibility and disabled/redeemed-peer checks on
registration, writes, and every delivery. Scoping a directory field does not
automatically authorize new endpoints, joins, or cached responses.

WireGuard has one configured PSK per peer, separate from established session
keys. It neither stages two PSKs nor automatically restores one after a
failed handshake. Updating the PSK need not replace an old session immediately.
Activation and strict-mode enforcement must account for this (section 5.6).
See the [WireGuard protocol](https://www.wireguard.com/protocol/) and
[Linux PSK update implementation](https://git.zx2c4.com/wireguard-linux/tree/drivers/net/wireguard/netlink.c).

Advertise `pq_psk_versions: [1]`; missing capability means unsupported.
Legacy clients retain their existing response shape. Versioned, paginated
PQ state is requested explicitly (section 5.2).

## 4. Non-goals

- Resistance to a compromised identity directory or active quantum attacker.
  An independent trust anchor and PQ identity authentication require a
  separate protocol revision.
- PSK-layer forward secrecy or post-compromise recovery following static
  KEM/DH-key compromise. Fresh encapsulation alone supplies neither.
- Seamless, atomic PSK replacement across two machines. Data-link interruption
  is accepted; partitions can extend it without disabling the API.
- Automatic rotation of the management PSK through its own protected tunnel,
  metadata hiding from the server, a general messaging service, or new
  NAT-traversal/listener infrastructure.
- Non-Linux support for this feature.

## 5. Proposed design

### 5.1 Data model and durable state

The directory has a random, persistent 16-byte `network_id`. Peer IDs are
positive integers at most `2^63 - 1`, stable and never reused within a
network. Server role is explicit metadata, not an assumption that restored
networks always give the server ID 1.

Each data peer advertises one atomic bundle:

- `pq_kem_public_key`, `pq_x448_public_key`, and `pq_sig_public_key`;
- `pq_version = 1`, a random 16-byte `bundle_id`, and a monotonic
  `bundle_revision` allocated by the server;
- its existing WireGuard public key and lifecycle state `enabled` or `retired`.

The new fields are nullable for legacy records. All absent means unsupported;
a partial, malformed, retired, or unsupported-version bundle is unusable,
not permission to downgrade. Registration is atomic and idempotent. Updates
use compare-and-swap against the current revision. Never reuse bundle IDs.

For each unordered data-peer pair, store at most one active exchange:
`(network_id, initiator_id, responder_id, initiator_bundle_id,
responder_bundle_id, sequence, exchange_id, transcript_hash, phase,
signed_messages, created_at, prepare_expires_at)`.

Phases are `proposed`, `ready`, `committed`, `complete`, and `aborted`.
After commitment, retain separate monotonic installation and fresh-handshake
confirmation receipts for each endpoint. Keep a compact terminal record with
the last sequence, exchange ID, transcript hash, and outcome for the current
bundle pair even after large bodies expire. Index both participants, active
phases, and expiry; enforce foreign keys.

Endpoints persist bundle secrets, high-water sequence marks, exact transcripts
and signed retries, candidate and previous confirmed PSKs, and installation/
confirmation intent. Key this state by network, peer IDs, and bundle IDs.
Private state is never uploaded. One process owns each interface under an
exclusive lock; multiple sync processes must not compete.

### 5.2 API, reliable delivery, and admission limits

- `PUT /v1/user/pq-keys` atomically registers/retires the caller's bundle.
  The authenticated session determines the sender. Initial registration
  expects no bundle; updates require the current revision.
  Retirement uses `?retire=1`; it must match the decoded lifecycle.
- `PUT /v1/user/pq-handshake/{other_peer_id}` submits a signed phase message.
  Section 5.5 defines transitions; section 5.14 defines exact bytes. Success
  means the transition and its receipt are committed to durable storage.
  Include `?phase=N` (the signed message type, 1–6) for pre-body admission;
  omission means propose. The hint must match the authenticated body. New
  proposals cannot consume capacity reserved for ready/commit/receipts/abort.
- `GET /v1/user/state?pq_version=1` returns visible bundles and exchanges in
  a versioned, paginated response. In this mode paginate both peers and PQ
  records: at most 1 MiB overall, 32 PQ records, and 128 KiB of PQ content
  per page. Continuation tokens are bound to requester and visibility
  revision. Recheck authorization per page; invalidated cursors restart the
  fetch. Legacy clients do not receive this new shape. Clients drain pages
  fairly and refresh changed bundles before accepting new exchanges.

GET never consumes a message. Duplicate delivery is expected. An identical
signed retry returns the recorded result; conflicting content for the same
exchange/sequence or an illegal transition returns 409. Use transactions/
compare-and-swap to serialize updates, expiry, retirement, and receipts.
An old acknowledgment must never delete or advance a newer exchange.

Before accepting a write, check current CIDR visibility, both peers' enabled/
redeemed status, complete current bundles, sender identity, pair roles,
size/encoding, and signature. Endpoints verify again before derivation or
installation. Reject self-addressing and server-link exchanges.

Initial configurable server limits are 8 KiB uncompressed request bodies,
a 5-second body-read deadline, 2 concurrent PQ writes per caller/64 globally,
token buckets of 8 writes/second with burst 16 per caller and 128/second
with burst 256 globally, and 64 active exchanges involving one peer/4096
globally. Enforce byte limits while reading, before JSON/base64 decoding;
reject unsupported content encodings and duplicate JSON fields. Bound
verification workers, log output, and database growth as well.

Quota exhaustion returns 429 with `Retry-After`; infrastructure saturation
may return 503. Reserve processing capacity for admitted exchanges and
ordinary state fetches: new proposals cannot starve completion, recovery,
or retirement. All requests remain rate-limited. These are service budgets,
not a claim of immunity to arbitrary flooding (section 7).

### 5.3 Key lifecycle, persistence, and upgrades

Introduce `--enable-pq-psk` in M1, before key generation or exchange behavior.
A never-enabled interface with the flag absent generates no keys, performs
no PQ writes, and keeps existing WireGuard behavior.

On first enablement, including an existing interface, generate the required
bundle once and persist it before registration. Use 0700 directories/0600
files, atomic writes, file/directory durability, and safe creation rejecting
symlink substitution. Do not place secrets in logs or command-line arguments.
Fail on randomness/persistence errors without registering half a bundle.
Erase intermediate secrets and retired keys after recovery obligations end.

On restart load confirmed/pending state before changing WireGuard, and
reconcile with the server through the independent management link. Persist
installation intent before touching the kernel and reapply/reconcile it
after crashes. Kernel configuration is not the only copy of a PSK.

Routine bundle replacement drains active exchanges before publishing a new
ID/revision atomically. Retain the last working PSK until the replacement
exchange completes, but do not encapsulate to retired keys. Pin the exact
bundles used by an outstanding exchange; refresh caches on revision changes.

Lost/corrupt private keys or replay state, revoked keys, and stale restored
backups require explicit identity recovery: block affected data links,
retire the bundle and its exchanges, generate a new bundle, and re-enroll
through the trusted directory. Never reset counters under an old bundle or
silently regenerate keys and resume its exchanges.

### 5.4 Pair roles, sequencing, and replay rejection

Only client-to-client data peers exchange through the mailbox. Lower peer
ID initiates; higher ID responds. Both enforce this assignment. Server links
have no mailbox role and follow section 5.10.

The initiator allocates a strictly increasing `sequence` for the current
bundle pair, persists it before sending, and generates a random 16-byte
`exchange_id`. Allow one outstanding exchange per pair. Counter exhaustion
requires bundle replacement, not wraparound.

After verifying identity/signature/context, the server and endpoints reject
sequences below their durable high-water marks. The same sequence is accepted
only for identical retries of that exchange in legal monotonic phases.
Earlier phases return the recorded outcome, never reinstalling a PSK.
Completion/abort permanently consumes the sequence for those bundle IDs.
A higher sequence cannot supersede a nonterminal exchange.

TTL is not replay protection. Obsolete generations/sequences remain invalid
when re-uploaded with fresh HTTP or server timestamps.

### 5.5 Exchange and explicit key confirmation

Every message is signed, identifies the same transcript, and travels through
the API. Directional HMAC tags confirm agreement on key material before
installation (sections 5.7 and 5.14).

1. **Propose — initiator.** Fetch and validate both current bundles. Generate
   a fresh combined ML-KEM-1024/X448 encapsulation and derive the PSK and two
   confirmation keys. Persist the candidate, transcript, sequence, and signed
   `propose` message, then upload it. Include the initiator confirmation
   tag; leave the current WireGuard PSK unchanged.
2. **Ready — responder.** On any state fetch verify bundle IDs, sequence,
   signature, and transcript. Decapsulate, derive, and verify the initiator's
   tag in constant time. Persist the candidate and signed `ready` tag, then
   upload it. Neither side has changed WireGuard yet.
3. **Commit — initiator.** Verify the responder's signature and tag. Persist
   a signed `commit` decision before upload. The server atomically advances
   `ready` to `committed` and returns a durable receipt. If the response is
   lost, query/retry this decision; do not assume failure or start another
   exchange. An already-terminal abort wins over a late commit.
4. **Install — responder, then initiator.** On observing commitment, the
   responder persists installation intent, applies section 5.6, and posts
   `installed`. Only after observing that authenticated receipt does the
   initiator install and post its own receipt. Retry receipts until durable.
5. **Confirm tunnel — both.** Observe a fresh authenticated WireGuard
   handshake under the new peer configuration and post signed `confirmed`
   receipts. A confirmation implies that side installed the candidate. The
   server marks complete only after both confirmations. Each endpoint
   persists the confirmed PSK/terminal outcome and erases superseded
   recovery secrets once no longer needed.

Loss, duplication, and reordering are expected at every step. Process
pending messages, retry receipts, and reconcile on every fetch independently
of rotation/idle settings. An old successful handshake or readback of a
configured PSK is not confirmation of this exchange.

### 5.6 Activation, cadence, and failure recovery

Default `--pq-psk-rotation-interval` is **300 seconds** on data clients.
Require a positive value and reject duration overflow. Schedule the next
rotation from completion using monotonic time. A short interval never
supersedes pending work: this is a target cadence, not an installation SLA.

Before commitment the previous working PSK remains installed. The initiator
can abort proposed/ready work; prepare expiry can also abort it. Persist the
terminal outcome before discarding candidates. Responder validation failure
leaves the kernel unchanged; without valid `ready`, commitment cannot occur.

After commitment, recover forward to the persisted candidate. Do not
independently restore an old PSK or clear the key because of timeout, missing
traffic, or temporary API failure. Committed work does not expire. Retry
kernel/configuration failures over the management link; irrecoverable state
loss follows section 5.3 and blocks the data link.

Version 1 accepts interruption for unambiguous activation. Gate application
traffic for the affected peer, remove only that WireGuard peer to discard
old sessions/in-flight handshakes, and recreate it with the candidate and
its full authorized configuration, including endpoints, allowed IPs, and
keepalive settings. Reconcile this sequence after crashes; never reset the
whole interface or unrelated peers. Fresh WireGuard keepalives can drive
confirmation while application traffic stays gated. Release the gate after
a fresh handshake and durable local confirmation; server completion also
requires the remote receipt.

The persistent fail-closed Linux gate must cover local and forwarded
traffic, IPv4/IPv6, and less-specific route fallback while a peer is absent.
Install it before strict enablement/recreation and restore it before bringing
an interface up after boot. Existing sessions/configuration cannot bypass
it. Handshake/keepalive probes are transport traffic, not an application
exception. M4 must implement and validate this gate, not merely set a PSK.

Do not report protection merely because public keys are advertised. Never
use a public-key-derived interim PSK. Preserve an operator's independent
secret PSK as the input in section 5.7, rather than replacing it with zero
or a public placeholder.

### 5.7 Hybrid combiner and operator PSKs

Let `T` be section 5.14's transcript and `H = SHA3-256`. `operator_psk` is a
provisioned 32-byte per-pair secret, or 32 zero bytes if neither side has one.
A nonzero public 16-byte `operator_psk_id` identifies an agreed provisioned
key; all-zero means absent. It is not a hash of the secret. Mismatched IDs
or confirmation tags fail before installation.

```text
IKM = ml_kem_shared_secret[32] || x448_shared_secret[56] || operator_psk[32]
PRK = HKDF-Extract-SHA3-256(salt = H(T), IKM = IKM)
psk = HKDF-Expand-SHA3-256(PRK, ASCII("innernet pq-psk v1 psk") || H(T), 32)
kc_i = HKDF-Expand-SHA3-256(PRK, ASCII("innernet pq-psk v1 confirm i") || H(T), 32)
kc_r = HKDF-Expand-SHA3-256(PRK, ASCII("innernet pq-psk v1 confirm r") || H(T), 32)
```

Use [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html) extract-then-expand
with HMAC-SHA3-256. Labels are exact ASCII without a terminating NUL. Do not
substitute a concatenation hash or use the PSK itself as a confirmation key.
M0 fixes interoperable vectors; M9 reviews the construction. Its intended
hedge depends on at least one input remaining secret. X448 is not an
independent post-quantum algorithm family.

Existing manually managed PSKs require explicit adoption into this feature's
protected state at both ends. Refuse ownership without that agreement. Never
mistake a previous feature-derived PSK for a new operator PSK. Disabling
requires section 5.11's coordinated policy transition.

### 5.8 Authentication and the trusted directory

ECDSA P-521/SHA-512 signatures are mandatory on proposals and all replies,
including commit, abort, installation, and confirmation. Bind network,
identities, and both complete bundles into the transcript. Validate current
revisions for a new exchange; retain exact bundles for its retries.

The directory authenticates registration through the existing peer session
and mediates replacement/retirement. Cached verification keys are not an
independent trust anchor. A compromised directory can replace signing, KEM,
X448, and WireGuard keys, suppress capabilities, or split views. It can still
impersonate peers despite signatures. Signing a ciphertext alone does not
authenticate the recipient's advertised KEM key.

Version 1 makes no server-compromise resistance claim. Independent pinning/
certification would require trusted enrollment, authenticated complete
bundles, and replacement/revocation rules, not just another signature field.

### 5.9 Expiry, cleanup, and bounded recovery state

Prepare TTL is **600 seconds** from first server acceptance and is not
extended by retries. Reads/writes atomically abort expired proposed/ready
work before returning or advancing it; a periodic sweep also compacts it.
No entry remains usable merely because the sweep has not run.

Commit acceptance and expiry serialize on the same record. After commitment,
TTL cannot delete recovery messages. Compact large bodies after completion
or abort, retaining the sequence/outcome tombstone until bundle retirement.
A lost terminal response resolves from that tombstone; obsolete bundle
messages remain invalid even after their rows are removed.

Recheck authorization on delivery. Visibility revocation, disabling a peer,
or emergency retirement blocks affected data links and terminates their
exchanges transactionally. No stale delivery can restore removed peers or
routes. Backups include directory identity/revisions and exchange state
together; a stale server restore requires reconciliation or explicit identity
recovery rather than reusing consumed sequences.

TTL limits uncommitted lifetime, not total storage. Admission quotas bound
active work, including committed records. Bound peer/history growth through
network admission/database budgets; never evict freshness state to make room.
Reserve disk capacity for admitted completion and expose stuck committed
exchanges to operators.

### 5.10 Management-link provisioning, rotation, and recovery

For new PQ enrollment, provision a fresh random 32-byte PSK per client-server
link. Deliver it with the pinned server WireGuard identity in the invitation
through an authenticated, confidential out-of-band channel appropriate to
the passive-quantum threat model. Do not first fetch it across a classically
protected WireGuard session whose historical encryption is the problem.

Persist it at both endpoints before enabling the link. Invitation redemption
carries the same PSK across the temporary-to-final-client WireGuard identity
transition, with durable server state. Remove consumed invitation secrets
when recovery obligations permit. Each client has a distinct PSK. The server
knows its own links' PSKs, not client-to-client exchange PSKs.

In PQ mode the link is management-only: allow the coordination API and
explicit bootstrap necessities, and deny general application/transit traffic
to or through the server. Keep it unaffected by data-peer rotations. Restore
all enrolled management PSKs before exposing the API after server reboot.
Provisioning must exist before strict PQ is advertised or M4 applies data PSKs.

Existing-network migration and subsequent management-PSK rotation require
administrator access independent of the affected tunnel (for example, console
or a separate management network). Preserve an existing trusted random PSK
when appropriate; enabling PQ does not automatically overwrite it. Rotation:

1. Generate a new per-link random secret and stage it durably at both ends
   over the independent access path, retaining the previous secret securely.
2. Arrange a maintenance window. Gate the link, persist installation intent,
   and replace only the affected peer configuration on both sides to remove
   old sessions. Apply the same new PSK and retain the management-only policy.
3. Verify a fresh WireGuard handshake and an authenticated API request. Mark
   the new PSK active durably on both ends before removing the previous one.
4. On failure use independent access to reconcile both ends, either applying
   the new secret to both or restoring the old secret to both. Never fall
   back to zero/public PSKs or expect the broken API tunnel to repair itself.

This is administrative rotation with a planned interruption, not automatic
mailbox rotation. Automating it requires an independent recovery channel
and a separately specified protocol; a separately keyed management tunnel
is one possible future design. Missing management secrets require out-of-band
repair. Server application links would need an independently recoverable
data interface/identity and are outside version 1. Static management PSKs
supply no PSK-layer forward secrecy even when periodically replaced.

### 5.11 Strict mode, permissive mode, and disabling

Strict `--enable-pq-psk` blocks data application traffic until a compatible
complete bundle, explicit key confirmation, and fresh PSK-protected handshake
succeed. The management-only link has its separately provisioned secret and
needs no mailbox enrollment.

`--pq-psk-permissive` requires enablement. It permits legacy WireGuard only
for peers with no PQ bundle that have never established PQ with this local
interface. Preserve any operator PSK. Partial/invalid bundles, failed
signatures, timeout, retirement, or disappearing capabilities after prior
success never trigger automatic fallback. Persist prior-PQ status and show
legacy/PQ/recovering/blocked states separately. A compromised trusted server
can still lie on first contact; section 5.8 defines that limitation.

Disabling a previously enabled interface is an explicit administrative
transition, not omitting a flag at restart; reject ambiguous startup options.
Drain active work or explicitly retire it while blocking traffic, publish
retirement atomically, stop new exchanges, and retain recovery/replay state
until retirement is durable. Remote strict peers remain blocked. Transition
to legacy requires local authorization at each endpoint and coordinated
restoration of the same operator PSK (zero only when both authorize no PSK).
Discard obsolete sessions before releasing traffic. Local opt-out cannot
force a remote downgrade or remove its gate.

### 5.12 Per-peer scheduling and tunnel inactivity

Default `--pq-psk-idle-timeout` is **900 seconds**; zero disables pausing.
It measures tunnel inactivity, not application inactivity: WireGuard byte
counters include handshake/keepalive traffic. A persistent-keepalive link
may never pause even without application traffic. The management link also
carries API traffic and is not a mailbox-rotation target.

Sample per-peer deltas on every state-fetch cycle. Counter reset, interface
recreation, or first observation establishes a new baseline and counts as
activity. Use monotonic elapsed time, never unsigned subtraction across a
reset. Pause only new rotations after the threshold. On the first activity
poll start an overdue rotation promptly, subject to admission limits;
do not wait an additional rotation interval.

Initial establishment, deliveries, reconciliation, and recovery never pause
for lack of traffic. Otherwise a broken/new link could need traffic to obtain
the key required for that traffic. Retry with bounded jittered backoff
(1–60 seconds, respecting `Retry-After`), checked by the existing sync
scheduler. Process due pairs fairly using per-pair state and bounded shared
workers. Idle peers must not restart a daemon or block others, but shared
CPU, database, and API budgets remain constraints.

### 5.13 Build targets and deployment support

Version 1 targets Linux x86_64/aarch64. M8 builds and executes cryptographic,
persistence, and WireGuard checks on both with declared system-library
versions. Dynamic linking requires target runtime packages, not only a
successful cross-link. Existing non-Linux builds retain legacy behavior and
reject unsupported PQ options explicitly. Linux-only scope is a project
choice, not a claim that the libraries cannot support other systems.

### 5.14 Canonical encoding and input validation

JSON binary fields use canonical RFC 4648 standard padded base64 without
whitespace. Reject alternate encodings, duplicate/unknown fields, missing
fields, unknown message types/versions, and trailing data. IDs, sequences,
and revisions use canonical unsigned decimal strings, not JSON numbers:
no leading zeros, nonzero, at most `2^63 - 1`. Encode these as unsigned
64-bit big-endian integers for signatures. Opaque IDs are 16-byte fields.

Define exact fixed-width bundle and transcript bytes:

```text
B = bundle_id[16] || bundle_revision[u64be] || wg_public_key[32]
    || pq_kem_public_key[1568] || pq_x448_public_key[56] || pq_sig_public_key[67]
T = ASCII("innernet pq-psk v1 transcript") || version[u8 = 1]
    || network_id[16] || initiator_id[u64be] || responder_id[u64be]
    || B_initiator || B_responder || sequence[u64be] || exchange_id[16]
    || operator_psk_id[16] || ciphertext[1624]
E = ASCII("innernet pq-psk v1 message") || version[u8 = 1]
    || network_id[16] || initiator_id[u64be] || responder_id[u64be]
    || initiator_bundle_id[16] || responder_bundle_id[16]
    || sequence[u64be] || exchange_id[16] || SHA3-256(T)[32]
    || sender_id[u64be] || message_type[u8]
tag = HMAC-SHA3-256(kc_sender, E)[32]
signature = ECDSA-P521-SHA512(E || tag)[132]
```

Bundles are the fixed-width B bytes, not JSON/base64 text. Literal labels
and hybrid ciphertext components have no struct padding. The ciphertext is
the 1568-byte ML-KEM component followed by the 56-byte ephemeral X448 public
key, in that order. Both shared-secret components feed section 5.7. Labels
have no trailing NUL/newline. Message codes are `propose=1`, `ready=2`,
`commit=3`, `installed=4`, `confirmed=5`, and `abort=6`. Only the initiator
sends propose/commit/abort, only the responder sends ready, and each sends
its own installed/confirmed receipts. `kc_sender` is `kc_i` or `kc_r` by role.

A JSON message carries the named E fields (`transcript_hash` for H(T)),
`tag`, and `signature`; `version` and `message_type` are JSON integer codes.
Only propose additionally carries `ciphertext` and
`operator_psk_id`; replies reference its persisted transcript. The receiver
reconstructs T from the proposal and exact directory bundles and checks its
hash before processing. No additional phase data is permitted. Abort is
accepted only before commitment. Transport receipts/timestamps are server
metadata, not signed peer-message fields.

Hash `E || tag` exactly once with SHA-512 through the configured ECDSA API.
Use [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979.html) deterministic
nonces with SHA-512 and fixed-width unsigned big-endian r/s (66 bytes each),
not DER. Enforce `1 <= r,s < n`, normalize to low-S (`s <= n/2`), and reject
high-S input. Persist signed bytes for identical retries. Validate compressed
P-521 points for curve membership and reject the identity point. M0 verifies
these library behaviors instead of relying on defaults.

Check ML-KEM public-key length and FIPS 203 modulus constraints before
encapsulation; check ciphertext length before decapsulation. A correctly
sized ciphertext for another key can return an implicit-rejection secret.
Do not expose its internal reject flag or treat a returned secret as success:
verify the confirmation tag. Check X448 input length, follow RFC 7748 decoding,
and reject an all-zero shared result in constant time. Any primitive,
encoding, or validation failure must not apply the candidate. Rate-limit
generic errors without exposing secret-dependent details.

M0 publishes fixed vectors for B/T/E, all message types, signatures, hybrid
derivation, and malformed inputs, including leading-zero signature integers
and independent-implementation agreement.

## 6. Security considerations

- **Passive quantum threat:** protection begins with the provisioned
  management PSK or a confirmed data PSK. Legacy permissive links without
  secret PSKs have no such protection; public placeholders add no secrecy.
- **Static-key compromise:** given recorded exchanges and a responder's
  static ML-KEM/X448 private keys, past derived PSKs can be reconstructed
  unless an independent operator PSK remains secret. Isolated derived-PSK
  compromise need not expose other encapsulations, but this is not forward
  secrecy after long-term-key compromise. This layer claims neither PQ
  forward secrecy nor post-compromise recovery.
- **Identity trust:** signatures stop forgery by ordinary peers under the
  trusted-directory model. They do not defeat directory key substitution,
  split views/suppression, or active quantum attacks on classical identities.
- **Replay/crashes:** authenticated context, durable high-water marks,
  monotonic phases, and generation retirement prevent obsolete installation.
  State loss that breaks these guarantees blocks links pending recovery.
- **Availability:** preparation preserves the current PSK; commitment can
  interrupt the pair and requires forward recovery. Progress needs reachable
  endpoints/relay. Independent management PSKs keep a data mismatch from
  itself disabling recovery, not from all possible network failures.
- **New workload:** an existing listener still gains parsing, crypto, storage,
  and contention. Enforce admission budgets before expensive operations and
  reserve resources for ordinary coordination.
- **Secret handling:** backups now include PSKs and protocol state. Protect
  permissions and lifetime. Secret comparisons are confined to isolated test
  builds, never production status, logs, telemetry, or CI artifacts.

## 7. Test plan and release evidence

Use deterministic unit tests for protocol invariants, real database/API
integration tests for durability, and Docker peers for network/kernel
behavior. [testing.md](testing.md) defines fixtures, unit coverage, container
setup, fault scenarios, and CI responsibilities. The cases below remain the
shared acceptance checklist across those layers.

### 7.1 Topology

Use one server container and at least five peers: cooperating `peer-a`/
`peer-b`, a third cooperating `peer-c` to verify unaffected links, cross-CIDR
adversary `peer-m`, and authorized flood source `peer-x`. Use an isolated
underlay with real WireGuard management/data paths, HTTP fault injection
that preserves peer identity, and separate persistent volumes for crash/
snapshot tests. Unit tests use virtual clocks; container tests respect real
kernel timers. Legacy binaries and extra simulated identities exercise
compatibility and admission limits.

### 7.2 Required cases

1. **Crypto interoperability:** independent encapsulate/decapsulate endpoints
   agree for one exchange; separate randomized exchanges differ. Check all
   section 5.14 vectors and directional confirmation tags.
2. **Strict activation:** no application traffic before a fresh candidate-key
   handshake, including old sessions, forwarding, IPv6, route fallback,
   and crashes during gate installation.
3. **Rotation:** complete repeated rotations, verify kernel PSKs and fresh
   handshakes, measure interruption, and keep unrelated peers connected.
4. **Lost/duplicate delivery:** drop every PUT response/state page in turn,
   duplicate/reorder phases, and verify eventual convergence without losing
   proposals, reinstalling old PSKs, or clearing working keys.
5. **Crash matrix:** restart either endpoint/server after each durable write,
   kernel change, and acknowledgment. Include kernel-only state loss,
   offline responders, and API outages beyond WireGuard session expiry.
6. **Commit/abort race:** exercise expiry, ready, commit, and abort in each
   relevant order. Only one decision wins; committed work never expires or
   independently rolls back.
7. **Replay rollback:** complete K0 then K1; replay every signed K0 phase
   and assert K1 remains installed. Repeat after restart, compaction,
   retirement, and stale-backup restoration.
8. **Validation:** reject malformed/partial bundles, encodings, invalid
   P-521 points/signatures, all-zero X448, invalid ML-KEM public keys,
   wrong-size and valid-size/wrong-generation ciphertexts. Use authorized
   senders so ACL rejection does not mask parsing/crypto checks.
9. **Context substitution:** alter network, IDs, bundles/revisions, sequence,
   type, ciphertext, or tag. Ordinary attacker/old signatures cannot
   authorize changed content. Reject unexpected senders and phase order.
10. **Directory trust boundary:** demonstrate malicious-directory key
    substitution during fresh enrollment as an expected limitation;
    distinguish it from ordinary-peer forgery, which must fail.
11. **CIDR/revocation:** reject unauthorized writes, spoofing, self/server
    targets, cross-page leaks, and delivery after removal/revocation;
    never recreate revoked peers or routes.
12. **Expiry/quotas:** reject expired preparation before a sweep; retries
    do not extend TTL. Committed recovery survives TTL and stale receipts
    cannot delete newer work. Exhaust quotas without evicting tombstones
    or starving admitted completion.
13. **Inactivity:** disable keepalives and stop traffic to test pause/resume
    on the next activity poll; a keepalive-only pair must not pause.
    Initial/pending/recovery work runs without traffic; counter resets
    and idle peers do not stall active peers.
14. **Flood/load:** record a 2-vCPU/2-GiB budget with 100 admitted identities;
    sustain 1000 PQ write attempts/second for 60 seconds. Assert bounded
    body/concurrency/record counts, rate limiting, RSS below 1 GiB, and
    ordinary state-fetch p99 below 2 seconds. With 1-second test polls,
    two previously admitted honest exchanges complete within 30 seconds.
    Report actual load/results; this is not arbitrary-flood immunity.
15. **Lifecycle/policy:** enable existing interfaces, interrupt registration,
    replace/lose keys, retire while committed, and disable/re-enable. Cover
    absent/partial/retired bundles, prior-PQ state, operator-PSK mismatch/
    preservation, and explicit bilateral downgrade.
16. **Management secrets:** test invitations/redemption, existing-network
    migration, reboot, and successful/failed administrative rotation using
    independent access. Data mismatch leaves API reachable; missing secrets
    block startup and general application/transit traffic is denied.
17. **Real compatibility:** execute old/new client/server and database
    upgrade/rollback/re-upgrade cases in section 10 with recorded versions;
    deserialization tests alone do not establish compatibility.
18. **Platforms:** run crypto, durability, gate, and WireGuard checks on
    Linux x86_64/aarch64 with system libraries; preserve non-Linux legacy
    builds with PQ disabled.

### 7.3 Acceptance

Every numbered case needs recorded results. Establish crypto vectors and
state-machine/crash checks before production PSK application; M9 completes
adversarial/load review before release. Record unit and Docker evidence
separately using the coverage manifest in [testing.md](testing.md); neither
test layer substitutes for the other. Secret dumps use owner-only test
storage excluded from logs/artifact uploads. This document does not claim
these tests or an external security audit have already run.

## 8. Exchange sequence and payload accounting

```mermaid
sequenceDiagram
    participant A as Data peer A (initiator)
    participant S as Coordination API (independent management PSKs)
    participant B as Data peer B (responder)
    A->>S: GET state with pq_version=1
    S-->>A: Complete KEM, X448, signing and WireGuard bundles
    Note over A: Persist candidate, sequence and signed proposal; keep current PSK
    A->>S: PUT pq-handshake/B (propose, ciphertext, tag, signature)
    S-->>A: Durable proposed receipt
    B->>S: GET state (every poll, non-consuming)
    S-->>B: Proposed exchange
    Note over B: Verify, derive, confirm tag and persist candidate
    B->>S: PUT pq-handshake/A (ready, tag, signature)
    A->>S: GET state
    S-->>A: Signed ready
    Note over A: Verify responder tag; persist commit intent
    A->>S: PUT pq-handshake/B (commit, tag, signature)
    S-->>A: Durable committed receipt
    B->>S: GET state
    S-->>B: Committed decision
    Note over B: Gate data; recreate only A's peer with candidate
    B->>S: PUT pq-handshake/A (installed, tag, signature)
    A->>S: GET state
    S-->>A: Responder installed receipt
    Note over A: Gate data; recreate only B's peer with candidate
    A->>S: PUT pq-handshake/B (installed, tag, signature)
    A->>B: Fresh WireGuard handshake and key confirmation
    Note over A,B: Persist local confirmation before releasing application gates
    A->>S: PUT pq-handshake/B (confirmed, tag, signature)
    B->>S: PUT pq-handshake/A (confirmed, tag, signature)
    S->>S: Complete; retain sequence/outcome tombstone
    Note over A,B: Reconcile completion on subsequent polls; retries are idempotent
```

| Material | Raw bytes | Padded base64 bytes |
| --- | ---: | ---: |
| ML-KEM public key or ciphertext | 1568 | 2092 |
| Hybrid ciphertext (ML-KEM ciphertext + ephemeral X448 public key) | 1624 | 2168 |
| X448 public key | 56 | 76 |
| Compressed P-521 public key | 67 | 92 |
| Three PQ keys (encoded separately) | 1691 | 2260 |
| P-521 signature | 132 | 176 |
| Confirmation tag | 32 | 44 |
| Hybrid ciphertext + signature + tag (encoded separately) | 1788 | 2388 |

Proposals add IDs, transcript hash, operator PSK ID, and JSON overhead to the
2388 bytes above. Replies omit ciphertext. Each message/registration must
fit the 8 KiB cap; M0 measures exact fixtures. GET follows section 5.2 page
caps. These are not UDP/MTU bounds: HTTP handles segmentation.

## 9. Alternatives considered

- A dedicated PQ listener/daemon could use a separately reviewed protocol
  and recovery path, with additional deployment/network-service work.
  Configuration restart requirements are implementation-specific, not an
  inherent property of a shared daemon.
- Large-public-key code-based KEMs need different distribution/bandwidth
  budgets and could add independent PQ-family diversity. X448 cannot supply
  that diversity against quantum attackers if ML-KEM fails. Large keys do
  not inherently require a separate listener.
- An out-of-band seeded hash ratchet can give PQ protection and, with
  erasure, protect earlier states. Missed steps can be recovered by advancing
  to an authenticated index with bounded catch-up; permanent desynchronization
  is not inherent. Full-mesh provisioning, rollback safety, and lack of
  automatic recovery after current-state compromise remain costs. This
  version uses out-of-band management/operator secrets, not a full mesh ratchet.
- Ephemeral KEM/DH keys or a reviewed ratcheting protocol could add forward
  secrecy, with additional generation, erasure, and offline-peer rules.
  Version 1 explicitly does not claim that property.
- Rotating the management PSK through its own tunnel requires an independent
  rescue path or separately justified recovery protocol. Version 1 chooses
  administrative rotation through independent access.
- Smaller parameter sets/single-library alternatives may reduce build/audit
  costs. Algorithm/encoding changes require a versioned design update and
  new vectors, never a silent runtime fallback.

## 10. Validation risks and migration rules

M0 records tested system-library versions, signing-library selection,
canonical vectors, and cross-compilation feasibility. M9 reviews the
combiner/state machine and validates the 300-second rotation, 900-second
inactivity threshold, 600-second prepare TTL, and service/load budgets.
These are validation tasks, not undecided signing policy or a vendoring option.

Select and record the supported innernet baseline commit and legacy binary
versions before implementation. M0 establishes build/test infrastructure
explicitly and records restored baseline code and its adaptations.

Migrations must be atomic/versioned with tested backup/restore and an explicit
compatibility matrix. New code rejects unknown newer schemas before any
write and never lowers version markers. Nullable columns alone do not prove
downgrade safety. In the pre-reset `7ca1b57` implementation,
`server/src/db/mod.rs` rewrites `user_version` whenever it differs, including
when a database is newer; a subsequent upgrade can then attempt to add
already-existing columns.

Do not promise arbitrary old-server access to migrated live databases.
Direct rollback is supported only for individually tested binaries proven
not to corrupt newer schema/version state. Otherwise stop the new server
and restore a matching pre-upgrade backup with matching endpoint policy and
management configuration through a coordinated rollback. Never restore old
exchange counters while endpoints keep the same bundle IDs; retire/re-enroll
affected identities as necessary.

Test old client/new server (PQ off and explicitly permissive), new client/old
server (PQ off/permissive/strict), and new/new combinations, plus database
new-to-old-to-new transitions and rejected unsupported rollbacks. Distinguish
wire compatibility, local policy, runtime dependencies, and database
compatibility in release notes. Installation on a never-enabled network
stays opt-in; strict enablement and management provisioning are explicit
behavior changes, not a claim of a behavior-free migration.
