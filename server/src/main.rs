use clap::{Parser, Subcommand};
use colored::*;
use innernet_shared::{
    AddCidrOpts, AddPeerOpts, DeleteCidrOpts, EnableDisablePeerOpts, HostsOpts, NetworkOpts,
    RenameCidrOpts, RenamePeerOpts,
};
use std::{env, path::PathBuf};

use innernet_server::{
    add_cidr, add_peer, apply_management_rotation, confirm_management_rotation, delete_cidr,
    enable_or_disable_peer,
    initialize::{self, InitializeOpts},
    mark_management_verified, rename_cidr, rename_peer, repair_management,
    rollback_management_rotation, serve, stage_management_rotation, uninstall, ServerConfig,
};
use innernet_shared::Interface;

#[derive(Debug, Parser)]
#[command(name = "innernet-server", author, version, about)]
struct Opts {
    #[clap(subcommand)]
    command: Command,

    #[clap(short, long, default_value = "/etc/innernet-server")]
    config_dir: PathBuf,

    #[cfg_attr(
        not(target_os = "openbsd"),
        clap(short, long, default_value = "/var/lib/innernet-server")
    )]
    #[cfg_attr(
        target_os = "openbsd",
        clap(short, long, default_value = "/var/db/innernet-server")
    )]
    data_dir: PathBuf,

    #[clap(flatten)]
    network: NetworkOpts,

    #[command(flatten)]
    pq: innernet_shared::pq::PqOptions,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a new network.
    #[clap(alias = "init")]
    New {
        #[clap(flatten)]
        opts: InitializeOpts,
    },

    /// Permanently uninstall a created network, rendering it unusable. Use with care.
    Uninstall {
        interface: Interface,

        /// Bypass confirmation
        #[clap(long)]
        yes: bool,
    },

    /// Serve the coordinating server for an existing network.
    Serve {
        interface: Interface,

        #[clap(flatten)]
        network: NetworkOpts,

        #[clap(flatten)]
        hosts: HostsOpts,
    },

    /// Add a peer to an existing network.
    AddPeer {
        interface: Interface,

        #[clap(flatten)]
        args: AddPeerOpts,
    },

    /// Disable an enabled peer
    DisablePeer {
        interface: Interface,

        #[clap(flatten)]
        args: EnableDisablePeerOpts,
    },

    /// Enable a disabled peer
    EnablePeer {
        interface: Interface,

        #[clap(flatten)]
        args: EnableDisablePeerOpts,
    },

    /// Rename an existing peer.
    RenamePeer {
        interface: Interface,

        #[clap(flatten)]
        args: RenamePeerOpts,
    },

    /// Add a new CIDR to an existing network.
    AddCidr {
        interface: Interface,

        #[clap(flatten)]
        args: AddCidrOpts,
    },

    /// Rename an existing CIDR.
    RenameCidr {
        interface: Interface,

        #[clap(flatten)]
        args: RenameCidrOpts,
    },

    /// Delete a CIDR.
    DeleteCidr {
        interface: Interface,

        #[clap(flatten)]
        args: DeleteCidrOpts,
    },

    /// Require the management-only link policy for an existing network,
    /// provisioning a management PSK for every currently enabled peer and
    /// installing the server-link traffic ACL on the next `serve`. New
    /// peers added afterward receive their link automatically through their
    /// invitation; this command is for retrofitting an existing network.
    RequireManagement {
        interface: Interface,

        /// Confirms this is being run over an access path independent of
        /// the affected tunnel (console, separate management network).
        #[clap(long)]
        independent_admin_access: bool,

        /// Optional JSON file mapping peer IDs to an already-trusted PSK to
        /// adopt instead of generating a fresh random one for that peer.
        #[clap(long)]
        adopted_psks: Option<PathBuf>,
    },

    /// Enable post-quantum data-peer PSKs for an existing network. Requires
    /// `require-management` to have already run for this network, so an
    /// independent recovery channel exists before any data PSK is
    /// exchanged.
    EnablePq { interface: Interface },

    /// Design 5.10 administrative rotation, step 1: stage a new management
    /// secret for one peer without touching the currently active, live one.
    /// Exports a transfer artifact for the client-side `stage-management`
    /// command; never automatic, never mailbox-driven.
    StageManagementRotation {
        interface: Interface,

        /// Name of the peer whose management link is being rotated.
        #[clap(long)]
        name: innernet_shared::Hostname,

        /// Confirms this is being run over an access path independent of
        /// the affected tunnel (console, separate management network).
        #[clap(long)]
        independent_admin_access: bool,

        /// Optional JSON file mapping peer IDs to an already-trusted PSK to
        /// adopt instead of generating a fresh random one.
        #[clap(long)]
        adopted_psks: Option<PathBuf>,
    },

    /// Design 5.10 step 2: replace the live secret with the staged one,
    /// pushing it into the live kernel peer entry immediately. The
    /// superseded secret is retained until `confirm-management-rotation`.
    ApplyManagementRotation {
        interface: Interface,

        #[clap(long)]
        name: innernet_shared::Hostname,

        #[clap(long)]
        independent_admin_access: bool,
    },

    /// Marks a peer's currently active management secret as verified
    /// (a real fresh handshake and authenticated API request succeeded),
    /// which `confirm-management-rotation` requires before it will discard
    /// the superseded secret.
    MarkManagementVerified {
        interface: Interface,

        #[clap(long)]
        name: innernet_shared::Hostname,

        #[clap(long)]
        independent_admin_access: bool,
    },

    /// Design 5.10 step 3: discard the superseded secret. Requires the
    /// currently active secret to already be marked verified.
    ConfirmManagementRotation {
        interface: Interface,

        #[clap(long)]
        name: innernet_shared::Hostname,

        #[clap(long)]
        independent_admin_access: bool,
    },

    /// Design 5.10 step 4: restore the secret that was active before the
    /// rotation attempt began, pushing it back into the live kernel peer
    /// entry immediately.
    RollbackManagementRotation {
        interface: Interface,

        #[clap(long)]
        name: innernet_shared::Hostname,

        #[clap(long)]
        independent_admin_access: bool,
    },

    /// Out-of-band repair for a mismatched installation: forces this side's
    /// active management secret to an explicitly provided value,
    /// independent of the other side's cooperation or any in-progress
    /// staged rotation.
    RepairManagement {
        interface: Interface,

        #[clap(long)]
        name: innernet_shared::Hostname,

        #[clap(long)]
        independent_admin_access: bool,

        /// JSON file mapping peer IDs to the trusted PSK to force.
        #[clap(long)]
        adopted_psks: PathBuf,
    },

    /// Generate shell completion scripts
    Completions {
        #[clap(value_enum)]
        shell: clap_complete::Shell,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::var_os("RUST_LOG").is_none() {
        // Set some default log settings.
        env::set_var("RUST_LOG", "warn,warp=info,wg_manage_server=info");
    }

    pretty_env_logger::init();
    let opts = Opts::parse();
    #[cfg(not(feature = "pq-dev-harness"))]
    opts.pq.production_ready()?;

    if unsafe { libc::getuid() } != 0 && !matches!(opts.command, Command::Completions { .. }) {
        return Err("innernet-server must run as root.".into());
    }

    let conf = ServerConfig::new(opts.config_dir, opts.data_dir);

    match opts.command {
        Command::New { opts } => {
            if let Err(e) = initialize::init_wizard(&conf, opts) {
                eprintln!("{}: {}.", "creation failed".red(), e);
                std::process::exit(1);
            }
        },
        Command::Uninstall { interface, yes } => uninstall(&interface, &conf, opts.network, yes)?,
        Command::Serve {
            interface,
            network: routing,
            hosts,
        } => serve(*interface, &conf, routing, hosts).await?,
        Command::AddPeer { interface, args } => add_peer(&interface, &conf, args, opts.network)?,
        Command::RenamePeer { interface, args } => rename_peer(&interface, &conf, args)?,
        Command::DisablePeer { interface, args } => {
            enable_or_disable_peer(&interface, &conf, false, opts.network, args)?
        },
        Command::EnablePeer { interface, args } => {
            enable_or_disable_peer(&interface, &conf, true, opts.network, args)?
        },
        Command::AddCidr { interface, args } => add_cidr(&interface, &conf, args)?,
        Command::RenameCidr { interface, args } => rename_cidr(&interface, &conf, args)?,
        Command::DeleteCidr { interface, args } => delete_cidr(&interface, &conf, args)?,
        Command::RequireManagement {
            interface,
            independent_admin_access,
            adopted_psks,
        } => {
            let path = innernet_server::management::prepare(
                &conf,
                &interface,
                independent_admin_access,
                adopted_psks.as_deref(),
            )?;
            println!(
                "{} management is now required for {}.",
                "[*]".dimmed(),
                interface
            );
            println!(
                "    Per-peer artifacts (if any peer needed one) were written under {}.",
                path.display()
            );
            println!(
                "    Transfer each peer-<id>.management.json confidentially and out of band, \
                 then restart `serve` to install the traffic policy.",
            );
        },
        Command::EnablePq { interface } => {
            innernet_server::enable_pq(&interface, &conf)?;
            println!(
                "{} post-quantum data-peer PSKs are now enabled for {}.",
                "[*]".dimmed(),
                interface
            );
        },
        Command::StageManagementRotation {
            interface,
            name,
            independent_admin_access,
            adopted_psks,
        } => {
            let path = stage_management_rotation(
                &interface,
                &conf,
                &name,
                independent_admin_access,
                adopted_psks.as_deref(),
            )?;
            println!(
                "{} a rotation candidate is staged for peer '{}'.",
                "[*]".dimmed(),
                name
            );
            println!(
                "    Transfer artifact written to {}; deliver it confidentially and out of \
                 band, then run `stage-management` on that peer before applying.",
                path.display()
            );
        },
        Command::ApplyManagementRotation {
            interface,
            name,
            independent_admin_access,
        } => {
            apply_management_rotation(
                &interface,
                &conf,
                &name,
                independent_admin_access,
                opts.network,
            )?;
            println!(
                "{} the staged secret is now active for peer '{}'; verify a fresh handshake \
                 and authenticated request before confirming.",
                "[*]".dimmed(),
                name
            );
        },
        Command::MarkManagementVerified {
            interface,
            name,
            independent_admin_access,
        } => {
            mark_management_verified(&interface, &conf, &name, independent_admin_access)?;
            println!(
                "{} peer '{}''s active management secret is marked verified.",
                "[*]".dimmed(),
                name
            );
        },
        Command::ConfirmManagementRotation {
            interface,
            name,
            independent_admin_access,
        } => {
            confirm_management_rotation(&interface, &conf, &name, independent_admin_access)?;
            println!(
                "{} the superseded secret for peer '{}' has been discarded.",
                "[*]".dimmed(),
                name
            );
        },
        Command::RollbackManagementRotation {
            interface,
            name,
            independent_admin_access,
        } => {
            rollback_management_rotation(
                &interface,
                &conf,
                &name,
                independent_admin_access,
                opts.network,
            )?;
            println!(
                "{} peer '{}' was rolled back to its pre-rotation secret.",
                "[*]".dimmed(),
                name
            );
        },
        Command::RepairManagement {
            interface,
            name,
            independent_admin_access,
            adopted_psks,
        } => {
            repair_management(
                &interface,
                &conf,
                &name,
                independent_admin_access,
                &adopted_psks,
                opts.network,
            )?;
            println!(
                "{} peer '{}''s management secret was forced to the provided value.",
                "[*]".dimmed(),
                name
            );
        },
        Command::Completions { shell } => {
            use clap::CommandFactory;
            let mut app = Opts::command();
            let app_name = app.get_name().to_string();
            clap_complete::generate(shell, &mut app, app_name, &mut std::io::stdout());
            std::process::exit(0);
        },
    }

    Ok(())
}
