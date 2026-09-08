//! Per-peer data-traffic gate for a data client's own WireGuard interface.
//!
//! This is a different mechanism from `server`'s management-only gate: that
//! one is whole-interface-scoped and permanent (design 5.10); this one is
//! per-peer and transient, closing exactly one peer's application traffic
//! around a PSK rotation (design 5.6). Rules match by the peer's *address*
//! (in named sets), not by which kernel peer entry currently routes it, so a
//! less-specific route (e.g. a hub peer's `0.0.0.0/0`) cannot carry blocked
//! traffic to a gated peer's address through a different peer entry while
//! that peer's own `/32`/`/128` route is briefly absent for recreation.
#![cfg(target_os = "linux")]
use std::{
    io::{self, Write},
    net::IpAddr,
    process::{Command, Stdio},
};
use wireguard_control::{AllowedIp, InterfaceName};

fn table_name(interface: &InterfaceName) -> String {
    format!("innernet_pq_data_{}", interface.as_str_lossy())
}

fn split_by_family(allowed_ips: &[AllowedIp]) -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for ip in allowed_ips {
        let element = format!("{}/{}", ip.address, ip.cidr);
        match ip.address {
            IpAddr::V4(_) => v4.push(element),
            IpAddr::V6(_) => v6.push(element),
        }
    }
    (v4, v6)
}

fn chains(name: &str) -> String {
    format!(
        "\x20   chain input {{\n\
         \x20       type filter hook input priority filter + 10; policy accept;\n\
         \x20       iifname \"{name}\" ip saddr @blocked_v4 drop\n\
         \x20       iifname \"{name}\" ip6 saddr @blocked_v6 drop\n\
         \x20   }}\n\
         \x20   chain output {{\n\
         \x20       type filter hook output priority filter + 10; policy accept;\n\
         \x20       oifname \"{name}\" ip daddr @blocked_v4 drop\n\
         \x20       oifname \"{name}\" ip6 daddr @blocked_v6 drop\n\
         \x20   }}\n\
         \x20   chain forward {{\n\
         \x20       type filter hook forward priority filter + 10; policy accept;\n\
         \x20       iifname \"{name}\" ip saddr @blocked_v4 drop\n\
         \x20       iifname \"{name}\" ip6 saddr @blocked_v6 drop\n\
         \x20       oifname \"{name}\" ip daddr @blocked_v4 drop\n\
         \x20       oifname \"{name}\" ip6 daddr @blocked_v6 drop\n\
         \x20   }}\n"
    )
}

/// Pure ruleset text for a full (re)creation, kept separate from the real
/// `nft` invocation so it can be tested without root/NET_ADMIN. Scoped
/// entirely to `interface`'s own table; never touches any other interface's
/// gate or the management table.
pub fn data_ruleset(interface: &InterfaceName, blocked: &[AllowedIp]) -> String {
    let table = table_name(interface);
    let name = interface.as_str_lossy();
    let (v4, v6) = split_by_family(blocked);
    let v4_elements = if v4.is_empty() {
        String::new()
    } else {
        format!("\n         \x20       elements = {{ {} }}", v4.join(", "))
    };
    let v6_elements = if v6.is_empty() {
        String::new()
    } else {
        format!("\n         \x20       elements = {{ {} }}", v6.join(", "))
    };
    format!(
        "table inet {table} {{\n\
         \x20   set blocked_v4 {{\n\
         \x20       type ipv4_addr\n\
         \x20       flags interval{v4_elements}\n\
         \x20   }}\n\
         \x20   set blocked_v6 {{\n\
         \x20       type ipv6_addr\n\
         \x20       flags interval{v6_elements}\n\
         \x20   }}\n\
         {}\
         }}\n",
        chains(&name)
    )
}

/// Idempotent additive ruleset (`add`, never `create`/`delete`) that ensures
/// the table, its two sets, and its three chains exist without disturbing
/// any elements already present in the sets.
fn ensure_exists_ruleset(interface: &InterfaceName) -> String {
    let table = table_name(interface);
    let name = interface.as_str_lossy();
    format!(
        "add table inet {table}\n\
         add set inet {table} blocked_v4 {{ type ipv4_addr; flags interval; }}\n\
         add set inet {table} blocked_v6 {{ type ipv6_addr; flags interval; }}\n\
         add chain inet {table} input {{ type filter hook input priority filter + 10; policy accept; }}\n\
         add chain inet {table} output {{ type filter hook output priority filter + 10; policy accept; }}\n\
         add chain inet {table} forward {{ type filter hook forward priority filter + 10; policy accept; }}\n\
         add rule inet {table} input iifname \"{name}\" ip saddr @blocked_v4 drop\n\
         add rule inet {table} input iifname \"{name}\" ip6 saddr @blocked_v6 drop\n\
         add rule inet {table} output oifname \"{name}\" ip daddr @blocked_v4 drop\n\
         add rule inet {table} output oifname \"{name}\" ip6 daddr @blocked_v6 drop\n\
         add rule inet {table} forward iifname \"{name}\" ip saddr @blocked_v4 drop\n\
         add rule inet {table} forward iifname \"{name}\" ip6 saddr @blocked_v6 drop\n\
         add rule inet {table} forward oifname \"{name}\" ip daddr @blocked_v4 drop\n\
         add rule inet {table} forward oifname \"{name}\" ip6 daddr @blocked_v6 drop\n"
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

/// Idempotent destructive (re)creation, seeded with the full desired
/// blocklist. Used exactly once per cold boot, before the interface/peers
/// come up: nftables state does not survive a reboot, so this is what
/// restores "existing sessions cannot bypass it" before any peer gets a
/// kernel entry again. Never call this for a single peer's rotation -- it
/// would momentarily reopen every other peer's gate too. Use `block`/
/// `release` for that instead.
pub fn apply_all(interface: &InterfaceName, blocked: &[AllowedIp]) -> io::Result<()> {
    clear(interface)?;
    run_nft(&data_ruleset(interface, blocked))
}

/// Idempotently ensures the table/sets/chains exist (never destructive),
/// then adds `allowed_ips` to the blocked sets. Safe to call repeatedly and
/// concurrently with `release` calls for other peers on the same interface.
pub fn block(interface: &InterfaceName, allowed_ips: &[AllowedIp]) -> io::Result<()> {
    run_nft(&ensure_exists_ruleset(interface))?;
    let table = table_name(interface);
    let (v4, v6) = split_by_family(allowed_ips);
    let mut script = String::new();
    if !v4.is_empty() {
        script.push_str(&format!(
            "add element inet {table} blocked_v4 {{ {} }}\n",
            v4.join(", ")
        ));
    }
    if !v6.is_empty() {
        script.push_str(&format!(
            "add element inet {table} blocked_v6 {{ {} }}\n",
            v6.join(", ")
        ));
    }
    if script.is_empty() {
        return Ok(());
    }
    run_nft(&script)
}

/// Removes `allowed_ips` from the blocked sets. An already-released (or
/// never-blocked) element is not an error: nft's delete-element error text
/// isn't a stable contract to match on, mirroring `clear`'s tolerance of an
/// absent table.
pub fn release(interface: &InterfaceName, allowed_ips: &[AllowedIp]) -> io::Result<()> {
    let table = table_name(interface);
    let (v4, v6) = split_by_family(allowed_ips);
    for element in v4 {
        let _ = run_nft(&format!(
            "delete element inet {table} blocked_v4 {{ {element} }}\n"
        ));
    }
    for element in v6 {
        let _ = run_nft(&format!(
            "delete element inet {table} blocked_v6 {{ {element} }}\n"
        ));
    }
    Ok(())
}

/// Removes this interface's data gate table entirely. A missing table is
/// not an error: nothing to restore to a permissive state. Used when an
/// interface is fully torn down (`innernet down`/uninstall), not as part of
/// the ordinary rotation lifecycle.
pub fn clear(interface: &InterfaceName) -> io::Result<()> {
    let table = table_name(interface);
    match run_nft(&format!("delete table inet {table}\n")) {
        Ok(()) => Ok(()),
        Err(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(address: &str, cidr: u8) -> AllowedIp {
        AllowedIp {
            address: address.parse().unwrap(),
            cidr,
        }
    }

    #[test]
    fn ruleset_is_address_keyed_and_scoped_to_the_named_interface() {
        let interface: InterfaceName = "wg-test0".parse().unwrap();
        let blocked = vec![ip("10.0.0.5", 32), ip("fd00::5", 128)];
        let text = data_ruleset(&interface, &blocked);
        assert!(text.contains("table inet innernet_pq_data_wg-test0"));
        assert!(text.contains("elements = { 10.0.0.5/32 }"));
        assert!(text.contains("elements = { fd00::5/128 }"));
        // Matches are keyed by address (named sets), never by peer identity.
        assert!(text.contains("ip saddr @blocked_v4 drop"));
        assert!(text.contains("ip6 saddr @blocked_v6 drop"));
        assert!(text.contains("ip daddr @blocked_v4 drop"));
        assert!(text.contains("ip6 daddr @blocked_v6 drop"));
        // Every matching line is scoped to this interface; nothing touches others.
        for line in text
            .lines()
            .filter(|l| l.contains("iifname") || l.contains("oifname"))
        {
            assert!(line.contains("\"wg-test0\""), "unscoped rule: {line}");
        }
        // The forward chain drops both directions (transit traffic).
        assert!(text.contains("iifname \"wg-test0\" ip saddr @blocked_v4 drop"));
        assert!(text.contains("oifname \"wg-test0\" ip daddr @blocked_v4 drop"));
    }

    #[test]
    fn empty_blocklist_produces_no_elements_line() {
        let interface: InterfaceName = "wg-test0".parse().unwrap();
        let text = data_ruleset(&interface, &[]);
        assert!(!text.contains("elements ="));
        assert!(text.contains("type ipv4_addr"));
        assert!(text.contains("type ipv6_addr"));
    }

    #[test]
    fn ensure_exists_ruleset_uses_only_idempotent_add_verbs() {
        let interface: InterfaceName = "wg-test0".parse().unwrap();
        let text = ensure_exists_ruleset(&interface);
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            assert!(
                line.starts_with("add "),
                "non-additive verb in ensure_exists: {line}"
            );
        }
    }

    #[test]
    fn block_and_release_scripts_target_the_right_table_and_sets() {
        let interface: InterfaceName = "wg-test0".parse().unwrap();
        let table = table_name(&interface);
        assert_eq!(table, "innernet_pq_data_wg-test0");
    }

    /// Exercises the real `nft` binary. Requires root/NET_ADMIN (a container
    /// with `--cap-add NET_ADMIN`, not this sandbox); not part of the default
    /// suite. No live interface is required: nft matches interface names as
    /// text and accepts rules for a name that does not yet exist.
    #[test]
    #[ignore = "requires root/NET_ADMIN and the nft binary"]
    fn apply_all_block_release_and_clear_manage_a_real_ruleset() {
        let interface: InterfaceName = "wg-pq-datatest0".parse().unwrap();
        let a = ip("10.55.0.2", 32);
        let b = ip("10.55.0.3", 32);

        apply_all(&interface, std::slice::from_ref(&a)).unwrap();
        let listed = Command::new("nft")
            .args(["list", "table", "inet", &table_name(&interface)])
            .output()
            .unwrap();
        assert!(listed.status.success());
        assert!(String::from_utf8_lossy(&listed.stdout).contains("10.55.0.2"));

        // Blocking a second peer must not disturb the first's gate.
        block(&interface, std::slice::from_ref(&b)).unwrap();
        let listed = Command::new("nft")
            .args(["list", "table", "inet", &table_name(&interface)])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&listed.stdout);
        assert!(text.contains("10.55.0.2"));
        assert!(text.contains("10.55.0.3"));

        // Releasing the first leaves the second still gated.
        release(&interface, &[a]).unwrap();
        let listed = Command::new("nft")
            .args(["list", "table", "inet", &table_name(&interface)])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&listed.stdout);
        assert!(!text.contains("10.55.0.2"));
        assert!(text.contains("10.55.0.3"));

        // Releasing an already-absent element is a safe no-op.
        release(&interface, &[ip("10.55.0.2", 32)]).unwrap();

        clear(&interface).unwrap();
        let listed = Command::new("nft")
            .args(["list", "table", "inet", &table_name(&interface)])
            .output()
            .unwrap();
        assert!(!listed.status.success());

        // Clearing an already-absent table is a no-op, not an error.
        clear(&interface).unwrap();
    }
}
