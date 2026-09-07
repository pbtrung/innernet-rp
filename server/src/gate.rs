//! Management-only traffic policy for a server's own WireGuard interface.
//!
//! This is narrower than the M4 data-peer traffic gate: it protects only the
//! server's own link, denying general application/transit traffic to or
//! through it while the coordination API stays reachable (design 5.10). It
//! never touches other interfaces or the host's own firewall rules.
#![cfg(target_os = "linux")]
use std::{
    io::{self, Write},
    process::{Command, Stdio},
};
use wireguard_control::InterfaceName;

const TABLE: &str = "innernet_pq_management";

/// Pure ruleset text, kept separate from the real `nft` invocation so it can
/// be tested without root/NET_ADMIN. Never applied elsewhere: it is scoped
/// entirely to packets entering/leaving `interface`.
pub fn management_ruleset(interface: &InterfaceName, api_port: u16) -> String {
    let name = interface.as_str_lossy();
    format!(
        "table inet {TABLE} {{\n\
         \x20   chain input {{\n\
         \x20       type filter hook input priority filter + 10; policy accept;\n\
         \x20       iifname \"{name}\" ct state established,related accept\n\
         \x20       iifname \"{name}\" icmp type {{ destination-unreachable, time-exceeded, parameter-problem }} accept\n\
         \x20       iifname \"{name}\" icmpv6 type {{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem }} accept\n\
         \x20       iifname \"{name}\" tcp dport {api_port} accept\n\
         \x20       iifname \"{name}\" drop\n\
         \x20   }}\n\
         \x20   chain forward {{\n\
         \x20       type filter hook forward priority filter + 10; policy accept;\n\
         \x20       iifname \"{name}\" drop\n\
         \x20       oifname \"{name}\" drop\n\
         \x20   }}\n\
         }}\n"
    )
}

fn run_nft(input: &str) -> io::Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(input.as_bytes())?;
    let output = child.wait_with_output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "nft failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// Idempotent: safe to call again on every `serve()` startup (including
/// after a reboot), replacing any prior ruleset with the current one.
pub fn apply(interface: &InterfaceName, api_port: u16) -> io::Result<()> {
    clear()?;
    run_nft(&management_ruleset(interface, api_port))
}

/// Removes the management-only table entirely. A missing table is not an
/// error: nothing to restore to a permissive state.
pub fn clear() -> io::Result<()> {
    match run_nft(&format!("delete table inet {TABLE}\n")) {
        Ok(()) => Ok(()),
        Err(_) => Ok(()), // absent table; nft's own error text isn't a stable contract to match on.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_scopes_every_rule_to_the_named_interface_and_allows_only_the_api_port() {
        let interface: InterfaceName = "wg-test0".parse().unwrap();
        let text = management_ruleset(&interface, 51820);
        assert!(text.contains("table inet innernet_pq_management"));
        assert!(text.contains("tcp dport 51820 accept"));
        // Every matching line is scoped to this interface; nothing touches others.
        for line in text
            .lines()
            .filter(|l| l.contains("iifname") || l.contains("oifname"))
        {
            assert!(line.contains("\"wg-test0\""), "unscoped rule: {line}");
        }
        // Both directions end in an explicit drop for unmatched traffic.
        assert!(text.contains("iifname \"wg-test0\" drop"));
        assert!(text.contains("oifname \"wg-test0\" drop"));
    }

    /// Exercises the real `nft` binary. Requires root/NET_ADMIN (a container
    /// with `--cap-add NET_ADMIN`, not this sandbox); not part of the default
    /// suite. No live `wg-pq-gatetest0` interface is required: nft matches
    /// interface names as text and accepts rules for a name that does not
    /// yet exist.
    #[test]
    #[ignore = "requires root/NET_ADMIN and the nft binary"]
    fn apply_installs_a_real_ruleset_and_clear_removes_it() {
        let interface: InterfaceName = "wg-pq-gatetest0".parse().unwrap();
        apply(&interface, 51820).unwrap();
        let listed = Command::new("nft")
            .args(["list", "table", "inet", TABLE])
            .output()
            .unwrap();
        assert!(listed.status.success());
        assert!(String::from_utf8_lossy(&listed.stdout).contains("wg-pq-gatetest0"));

        // Idempotent: reapplying (as a `serve` restart would) does not error
        // or duplicate the table.
        apply(&interface, 51820).unwrap();

        clear().unwrap();
        let listed = Command::new("nft")
            .args(["list", "table", "inet", TABLE])
            .output()
            .unwrap();
        assert!(!listed.status.success());

        // Clearing an already-absent table is a no-op, not an error.
        clear().unwrap();
    }
}
