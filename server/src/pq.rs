//! Bounded admission independent of SQLite and normal coordination requests.
use crate::ServerError;
use innernet_pq::crypto::{self, Secret, SystemRandom};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub peer_active: u32,
    pub global_active: u32,
    pub peer_writes: usize,
    pub global_writes: usize,
    pub peer_rate: u32,
    pub peer_burst: u32,
    pub global_rate: u32,
    pub global_burst: u32,
    pub peer_ids: u32,
    pub bundle_ids: u32,
    pub database_bytes: u64,
    pub recovery_reserve_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            peer_active: 64,
            global_active: 4096,
            peer_writes: 2,
            global_writes: 64,
            peer_rate: 8,
            peer_burst: 16,
            global_rate: 128,
            global_burst: 256,
            peer_ids: 10_000,
            bundle_ids: 100_000,
            database_bytes: 256 * 1024 * 1024,
            recovery_reserve_bytes: 32 * 1024 * 1024,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<(), ServerError> {
        if self.peer_writes < 2
            || self.global_writes < 2
            || self.peer_writes > self.global_writes
            || self.global_writes > 256
            || self.peer_rate < 2
            || self.global_rate < 2
            || self.peer_burst < 2
            || self.global_burst < 2
            || self.peer_active == 0
            || self.global_active == 0
            || self.peer_ids == 0
            || self.bundle_ids == 0
            || self.database_bytes <= self.recovery_reserve_bytes
            || self.recovery_reserve_bytes < u64::from(self.global_active) * 4096
        {
            return Err(ServerError::InvalidQuery);
        }
        Ok(())
    }
}

pub trait Clock: Send + Sync {
    fn monotonic_ms(&self) -> u64;
    fn epoch_seconds(&self) -> u64;
}
struct SystemClock(Instant);
impl Clock for SystemClock {
    fn monotonic_ms(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
    fn epoch_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}
#[derive(Clone)]
struct Bucket {
    tokens: u64,
    last: u64,
    rate: u32,
    burst: u32,
}
impl Bucket {
    fn new(rate: u32, burst: u32, now: u64) -> Self {
        Self {
            tokens: u64::from(burst) * 1000,
            last: now,
            rate,
            burst,
        }
    }
    fn take(&mut self, now: u64) -> bool {
        let elapsed = now.saturating_sub(self.last);
        self.tokens = self
            .tokens
            .saturating_add(elapsed.saturating_mul(u64::from(self.rate)))
            .min(u64::from(self.burst) * 1000);
        self.last = self.last.max(now);
        if self.tokens < 1000 {
            false
        } else {
            self.tokens -= 1000;
            true
        }
    }
}
struct Caller {
    writes: Arc<Semaphore>,
    new_writes: Arc<Semaphore>,
    all: Bucket,
    new: Bucket,
}
struct Admission {
    all: Bucket,
    new: Bucket,
    peers: HashMap<i64, Caller>,
}

pub struct Service {
    pub limits: Limits,
    pub clock: Arc<dyn Clock>,
    pub(crate) cursor_key: Secret<32>,
    writes: Arc<Semaphore>,
    new_writes: Arc<Semaphore>,
    reads: Arc<Semaphore>,
    admission: Mutex<Admission>,
}
pub struct Permit {
    _permits: Vec<OwnedSemaphorePermit>,
}
impl Service {
    pub fn new(limits: Limits) -> Result<Self, ServerError> {
        Self::with_clock(limits, Arc::new(SystemClock(Instant::now())))
    }
    pub(crate) fn with_clock(limits: Limits, clock: Arc<dyn Clock>) -> Result<Self, ServerError> {
        limits.validate()?;
        let now = clock.monotonic_ms();
        Ok(Self {
            cursor_key: crypto::random(&mut SystemRandom)?,
            writes: Arc::new(Semaphore::new(limits.global_writes)),
            reads: Arc::new(Semaphore::new(8)),
            new_writes: Arc::new(Semaphore::new(
                limits.global_writes - (limits.global_writes / 4).max(1),
            )),
            admission: Mutex::new(Admission {
                all: Bucket::new(limits.global_rate, limits.global_burst, now),
                new: Bucket::new(limits.global_rate / 2, limits.global_burst / 2, now),
                peers: HashMap::new(),
            }),
            clock,
            limits,
        })
    }
    /// Reserve before reading/decoding bodies. Existing exchanges, retirement,
    /// and their retries use the reserved recovery capacity, but remain limited.
    pub fn admit(&self, peer: i64, new: bool) -> Result<Permit, ServerError> {
        let now = self.clock.monotonic_ms();
        let mut admission = self
            .admission
            .lock()
            .map_err(|_| ServerError::Unavailable)?;
        if !admission.peers.contains_key(&peer)
            && admission.peers.len() >= self.limits.peer_ids as usize
        {
            return Err(ServerError::RateLimited);
        }
        // Test all token buckets against snapshots, then debit atomically.
        // Rejected new-work floods must not drain the recovery reservation.
        let mut global_all = admission.all.clone();
        let mut global_new = admission.new.clone();
        if (new && !global_new.take(now)) || !global_all.take(now) {
            return Err(ServerError::RateLimited);
        }
        let caller = admission.peers.entry(peer).or_insert_with(|| Caller {
            writes: Arc::new(Semaphore::new(self.limits.peer_writes)),
            new_writes: Arc::new(Semaphore::new(self.limits.peer_writes - 1)),
            all: Bucket::new(self.limits.peer_rate, self.limits.peer_burst, now),
            new: Bucket::new(self.limits.peer_rate / 2, self.limits.peer_burst / 2, now),
        });
        let mut caller_all = caller.all.clone();
        let mut caller_new = caller.new.clone();
        if (new && !caller_new.take(now)) || !caller_all.take(now) {
            return Err(ServerError::RateLimited);
        }
        let mut permits = vec![
            self.writes
                .clone()
                .try_acquire_owned()
                .map_err(|_| ServerError::RateLimited)?,
            caller
                .writes
                .clone()
                .try_acquire_owned()
                .map_err(|_| ServerError::RateLimited)?,
        ];
        if new {
            permits.push(
                self.new_writes
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| ServerError::RateLimited)?,
            );
            permits.push(
                caller
                    .new_writes
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| ServerError::RateLimited)?,
            );
        }
        caller.all = caller_all;
        caller.new = caller_new;
        admission.all = global_all;
        admission.new = global_new;
        Ok(Permit { _permits: permits })
    }
    pub fn admit_read(&self) -> Result<OwnedSemaphorePermit, ServerError> {
        self.reads
            .clone()
            .try_acquire_owned()
            .map_err(|_| ServerError::RateLimited)
    }
}
