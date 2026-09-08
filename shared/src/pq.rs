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

    /// M1–M3 expose implementations only to isolated development/test callers.
    pub fn production_ready(&self) -> Result<(), &'static str> {
        self.validate()?;
        if self.enable_pq_psk {
            return Err("production PQ activation is unavailable until management recovery and the persistent traffic gate are installed and verified");
        }
        Ok(())
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
    fn enablement_is_opt_in_and_production_fails_closed_before_side_effects() {
        let off = Cli::try_parse_from(["test"]).unwrap();
        off.pq.production_ready().unwrap();
        assert!(Cli::try_parse_from(["test", "--pq-psk-permissive"]).is_err());
        let enabled =
            Cli::try_parse_from(["test", "--enable-pq-psk", "--pq-psk-permissive"]).unwrap();
        assert!(enabled.pq.production_ready().is_err());
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
