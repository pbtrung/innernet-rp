//! Checked, fixed-width bindings to leancrypto and OpenSSL system libraries.
use crate::{Error, Result};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

unsafe extern "C" {
    fn pq_init() -> i32;
    fn pq_hybrid_keygen(
        pk: *mut u8,
        xpk: *mut u8,
        sk: *mut u8,
        xsk: *mut u8,
        seed: *const u8,
    ) -> i32;
    fn pq_hybrid_public(pk: *mut u8, xpk: *mut u8, sk: *const u8, xsk: *const u8) -> i32;
    fn pq_hybrid_enc(ct: *mut u8, ss: *mut u8, xss: *mut u8, pk: *const u8, xpk: *const u8) -> i32;
    fn pq_hybrid_dec(
        ss: *mut u8,
        xss: *mut u8,
        ct: *const u8,
        sk: *const u8,
        xsk: *const u8,
    ) -> i32;
    fn pq_x448_validate(pk: *const u8) -> i32;
    fn pq_hash(out: *mut u8, data: *const u8, len: usize) -> i32;
    fn pq_hmac(out: *mut u8, key: *const u8, data: *const u8, len: usize) -> i32;
    fn pq_hkdf(out: *mut u8, ikm: *const u8, salt: *const u8, info: *const u8, len: usize) -> i32;
    fn pq_sign_public(out: *mut u8, sk: *const u8) -> i32;
    fn pq_sign_validate(pk: *const u8) -> i32;
    fn pq_sign(out: *mut u8, sk: *const u8, data: *const u8, len: usize) -> i32;
    fn pq_verify(raw: *const u8, pk: *const u8, data: *const u8, len: usize) -> i32;
}

fn invoke(operation: impl FnOnce() -> i32) -> Result<()> {
    static INITIALIZED: std::sync::OnceLock<i32> = std::sync::OnceLock::new();
    // SAFETY: all library calls pass through this barrier; initialization cannot
    // race another operation or alter global leancrypto state while it is in use.
    let status = *INITIALIZED.get_or_init(|| unsafe { pq_init() });
    if status != 0 || operation() != 0 {
        Err(Error::Crypto)
    } else {
        Ok(())
    }
}

/// Deliberately has no Debug, Display, or serialization implementation.
pub struct Secret<const N: usize>(pub Zeroizing<[u8; N]>);
impl<const N: usize> Secret<N> {
    pub fn from_bytes(bytes: [u8; N]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn same(&self, other: &Self) -> bool {
        bool::from(self.0.as_slice().ct_eq(other.0.as_slice()))
    }
}

pub trait Random {
    fn fill(&mut self, output: &mut [u8]) -> Result<()>;
}
pub struct SystemRandom;
impl Random for SystemRandom {
    fn fill(&mut self, output: &mut [u8]) -> Result<()> {
        getrandom::fill(output).map_err(|_| Error::Random)
    }
}

pub fn random<const N: usize>(rng: &mut impl Random) -> Result<Secret<N>> {
    let mut secret = Secret::from_bytes([0; N]);
    rng.fill(secret.0.as_mut_slice())?;
    Ok(secret)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridPublic {
    pub kem: [u8; 1568],
    pub x448: [u8; 56],
}
pub struct HybridSecret {
    pub kem: Secret<3168>,
    pub x448: Secret<56>,
}
pub struct HybridShared {
    pub kem: Secret<32>,
    pub x448: Secret<56>,
}
impl HybridShared {
    pub fn same(&self, other: &Self) -> bool {
        self.kem.same(&other.kem) & self.x448.same(&other.x448)
    }
}

pub fn hybrid_keypair(rng: &mut impl Random) -> Result<(HybridPublic, HybridSecret)> {
    let seed = random::<64>(rng)?;
    let mut public = HybridPublic {
        kem: [0; 1568],
        x448: [0; 56],
    };
    let mut secret = HybridSecret {
        kem: Secret::from_bytes([0; 3168]),
        x448: Secret::from_bytes([0; 56]),
    };
    // SAFETY: pointers refer to live nonoverlapping arrays of the ABI's exact sizes.
    invoke(|| unsafe {
        pq_hybrid_keygen(
            public.kem.as_mut_ptr(),
            public.x448.as_mut_ptr(),
            secret.kem.0.as_mut_ptr(),
            secret.x448.0.as_mut_ptr(),
            seed.0.as_ptr(),
        )
    })?;
    Ok((public, secret))
}

pub fn hybrid_public(secret: &HybridSecret) -> Result<HybridPublic> {
    let mut public = HybridPublic {
        kem: [0; 1568],
        x448: [0; 56],
    };
    // SAFETY: fixed-size component buffers; generic library structs stay in C.
    invoke(|| unsafe {
        pq_hybrid_public(
            public.kem.as_mut_ptr(),
            public.x448.as_mut_ptr(),
            secret.kem.0.as_ptr(),
            secret.x448.0.as_ptr(),
        )
    })?;
    Ok(public)
}

pub fn validate_kem(public: &[u8; 1568]) -> Result<()> {
    // FIPS 203 encapsulation-key modulus check over ByteDecode_12(t_hat).
    for bytes in public[..1536].as_chunks::<3>().0 {
        let a = u16::from(bytes[0]) | (u16::from(bytes[1] & 15) << 8);
        let b = u16::from(bytes[1] >> 4) | (u16::from(bytes[2]) << 4);
        if a >= 3329 || b >= 3329 {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}

pub fn validate_x448(public: &[u8; 56]) -> Result<()> {
    // SAFETY: the bridge reads exactly 56 public bytes.
    invoke(|| unsafe { pq_x448_validate(public.as_ptr()) })
}

pub fn encapsulate(public: &HybridPublic) -> Result<([u8; 1624], HybridShared)> {
    validate_kem(&public.kem)?;
    let mut ciphertext = [0; 1624];
    let mut shared = HybridShared {
        kem: Secret::from_bytes([0; 32]),
        x448: Secret::from_bytes([0; 56]),
    };
    // SAFETY: exact fixed-width arrays; the library supplies its seeded system RNG.
    invoke(|| unsafe {
        pq_hybrid_enc(
            ciphertext.as_mut_ptr(),
            shared.kem.0.as_mut_ptr(),
            shared.x448.0.as_mut_ptr(),
            public.kem.as_ptr(),
            public.x448.as_ptr(),
        )
    })?;
    Ok((ciphertext, shared))
}

/// The caller must authenticate a directional confirmation tag before use.
/// A returned secret is not evidence that decapsulation accepted the ciphertext.
pub fn decapsulate(ciphertext: &[u8; 1624], private: &HybridSecret) -> Result<HybridShared> {
    let mut shared = HybridShared {
        kem: Secret::from_bytes([0; 32]),
        x448: Secret::from_bytes([0; 56]),
    };
    // SAFETY: exact fixed-width arrays, with no aliases to the output.
    invoke(|| unsafe {
        pq_hybrid_dec(
            shared.kem.0.as_mut_ptr(),
            shared.x448.0.as_mut_ptr(),
            ciphertext.as_ptr(),
            private.kem.0.as_ptr(),
            private.x448.0.as_ptr(),
        )
    })?;
    Ok(shared)
}

pub fn hash(data: &[u8]) -> Result<[u8; 32]> {
    let mut digest = [0; 32];
    // SAFETY: digest has the SHA3-256 output size; data length matches its slice.
    invoke(|| unsafe { pq_hash(digest.as_mut_ptr(), data.as_ptr(), data.len()) })?;
    Ok(digest)
}
pub fn tag(key: &Secret<32>, data: &[u8]) -> Result<[u8; 32]> {
    let mut output = [0; 32];
    // SAFETY: output/key have the ABI's fixed sizes; data is a live slice.
    invoke(|| unsafe {
        pq_hmac(
            output.as_mut_ptr(),
            key.0.as_ptr(),
            data.as_ptr(),
            data.len(),
        )
    })?;
    Ok(output)
}

pub struct Candidate {
    pub psk: Secret<32>,
    pub initiator_confirmation: Secret<32>,
    pub responder_confirmation: Secret<32>,
}
pub fn derive(
    kem: &Secret<32>,
    dh: &Secret<56>,
    operator: &Secret<32>,
    transcript: &[u8],
) -> Result<Candidate> {
    let mut ikm = Zeroizing::new([0; 120]);
    ikm[..32].copy_from_slice(kem.0.as_slice());
    ikm[32..88].copy_from_slice(dh.0.as_slice());
    ikm[88..].copy_from_slice(operator.0.as_slice());
    let salt = hash(transcript)?;
    let expand = |label: &[u8]| -> Result<Secret<32>> {
        let mut info = label.to_vec();
        info.extend_from_slice(&salt);
        let mut out = Secret::from_bytes([0; 32]);
        // SAFETY: IKM/salt/output have fixed ABI sizes and info is a live slice.
        invoke(|| unsafe {
            pq_hkdf(
                out.0.as_mut_ptr(),
                ikm.as_ptr(),
                salt.as_ptr(),
                info.as_ptr(),
                info.len(),
            )
        })?;
        Ok(out)
    };
    Ok(Candidate {
        psk: expand(b"innernet pq-psk v1 psk")?,
        initiator_confirmation: expand(b"innernet pq-psk v1 confirm i")?,
        responder_confirmation: expand(b"innernet pq-psk v1 confirm r")?,
    })
}
pub fn signing_public(private: &Secret<66>) -> Result<[u8; 67]> {
    let mut public = [0; 67];
    // SAFETY: exact ABI buffer sizes and live references.
    invoke(|| unsafe { pq_sign_public(public.as_mut_ptr(), private.0.as_ptr()) })?;
    Ok(public)
}
pub fn signing_keypair(rng: &mut impl Random) -> Result<([u8; 67], Secret<66>)> {
    // Rejection sampling in [1,n). Bound faulty/test RNG behavior.
    for _ in 0..128 {
        let mut private = random::<66>(rng)?;
        private.0[0] &= 1;
        if let Ok(public) = signing_public(&private) {
            return Ok((public, private));
        }
    }
    Err(Error::Random)
}
pub fn validate_signing(public: &[u8; 67]) -> Result<()> {
    // SAFETY: fixed-width compressed SEC1 array.
    invoke(|| unsafe { pq_sign_validate(public.as_ptr()) })
}
pub fn sign(private: &Secret<66>, data: &[u8]) -> Result<[u8; 132]> {
    let mut signature = [0; 132];
    // SAFETY: exact key/signature sizes, and the data pointer matches its length.
    invoke(|| unsafe {
        pq_sign(
            signature.as_mut_ptr(),
            private.0.as_ptr(),
            data.as_ptr(),
            data.len(),
        )
    })?;
    Ok(signature)
}
pub fn verify(public: &[u8; 67], signature: &[u8; 132], data: &[u8]) -> Result<()> {
    // SAFETY: exact public key/signature sizes; validation is performed by the bridge.
    invoke(|| unsafe {
        pq_verify(
            signature.as_ptr(),
            public.as_ptr(),
            data.as_ptr(),
            data.len(),
        )
    })
}
