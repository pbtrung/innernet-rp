//! Feature policy is checked before key generation, requests, or kernel changes.
use clap::Args;

#[derive(Args, Clone, Debug, Default)]
pub struct PqOptions {
    /// Enable authenticated post-quantum data PSKs (requires provisioned recovery).
    #[arg(long, global = true)]
    pub enable_pq_psk: bool,
    /// Permit entirely legacy peers, but never silently downgrade a PQ relationship.
    #[arg(long, global = true, requires = "enable_pq_psk")]
    pub pq_psk_permissive: bool,
}

impl PqOptions {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.pq_psk_permissive && !self.enable_pq_psk {
            return Err("--pq-psk-permissive requires --enable-pq-psk");
        }
        if self.enable_pq_psk && !cfg!(target_os = "linux") {
            return Err("PQ PSKs are supported only on Linux");
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
}
