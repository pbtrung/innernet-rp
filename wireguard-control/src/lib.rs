use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

pub mod backends;
mod config;
mod device;
mod key;

pub use crate::{config::*, device::*, key::*};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Backend {
    #[default]
    Kernel,
    Userspace,
}

impl Display for Backend {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kernel => write!(f, "kernel"),
            Self::Userspace => write!(f, "userspace"),
        }
    }
}

impl FromStr for Backend {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "kernel" => Ok(Self::Kernel),
            "userspace" => Ok(Self::Userspace),
            _ => Err(format!("valid values: {}.", Self::variants().join(", "))),
        }
    }
}

impl Backend {
    pub fn variants() -> &'static [&'static str] {
        &["kernel", "userspace"]
    }
}
