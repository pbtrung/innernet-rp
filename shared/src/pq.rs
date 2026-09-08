//! Feature policy is checked before key generation, requests, or kernel changes.
use clap::Args;

#[derive(Args, Clone, Debug)]
pub struct PqOptions {
    /// Enable authenticated post-quantum data PSKs (requires provisioned recovery).
    #[arg(long, global = true)]
    pub enable_pq_psk: bool,
    /// Permit entirely legacy peers, but never silently downgrade a PQ relationship.
    #[arg(long, global = true, requires = "enable_pq_psk")]
    pub pq_psk_permissive: bool,
    /// Target cadence between completed data-peer PSK rotations, in seconds.
    /// Meaningful only on data clients; the server never reads it. A short
    /// interval never supersedes pending work: this is a target, not an SLA.
    #[arg(long, global = true, default_value = "300")]
    pub pq_psk_rotation_interval: u64,
}

impl Default for PqOptions {
    fn default() -> Self {
        Self {
            enable_pq_psk: false,
            pq_psk_permissive: false,
            pq_psk_rotation_interval: 300,
        }
    }
}

impl PqOptions {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.pq_psk_permissive && !self.enable_pq_psk {
            return Err("--pq-psk-permissive requires --enable-pq-psk");
        }
        if self.enable_pq_psk && !cfg!(target_os = "linux") {
            return Err("PQ PSKs are supported only on Linux");
        }
        // A generous bound, not a claim of realistic use: comfortably below
        // any value that could overflow later monotonic-clock arithmetic.
        if self.pq_psk_rotation_interval == 0 || self.pq_psk_rotation_interval > u64::MAX / 4 {
            return Err("--pq-psk-rotation-interval must be positive and non-overflowing");
        }
        Ok(())
    }

    /// M1-M3 confined enablement to isolated development/test callers,
    /// pending the two preconditions this comment used to name: management
    /// recovery (M2) and a persistent, real per-peer traffic gate with a
    /// real kernel installer (M4). Both now exist and are Docker-verified,
    /// so production activation is unconditional here; `validate` above is
    /// the only remaining check.
    pub fn production_ready(&self) -> Result<(), &'static str> {
        self.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        pq: PqOptions,
    }

    #[test]
    fn enablement_is_opt_in_and_permissive_requires_it() {
        let off = Cli::try_parse_from(["test"]).unwrap();
        off.pq.production_ready().unwrap();
        assert!(!off.pq.enable_pq_psk);
        assert!(Cli::try_parse_from(["test", "--pq-psk-permissive"]).is_err());
    }

    #[test]
    fn production_ready_now_accepts_real_activation() {
        // M4 lifted the M1-M3 refusal: real per-peer gate + installer exist.
        let enabled =
            Cli::try_parse_from(["test", "--enable-pq-psk", "--pq-psk-permissive"]).unwrap();
        enabled.pq.production_ready().unwrap();
    }

    #[test]
    fn rotation_interval_defaults_and_rejects_zero_or_overflow() {
        let default = Cli::try_parse_from(["test"]).unwrap();
        assert_eq!(default.pq.pq_psk_rotation_interval, 300);
        default.pq.validate().unwrap();
        assert!(
            Cli::try_parse_from(["test", "--pq-psk-rotation-interval", "0"])
                .unwrap()
                .pq
                .validate()
                .is_err()
        );
        assert!(
            Cli::try_parse_from(["test", "--pq-psk-rotation-interval", &u64::MAX.to_string()])
                .unwrap()
                .pq
                .validate()
                .is_err()
        );
        assert!(
            Cli::try_parse_from(["test", "--pq-psk-rotation-interval", "1"])
                .unwrap()
                .pq
                .validate()
                .is_ok()
        );
    }
}
