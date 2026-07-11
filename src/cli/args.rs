use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Parser)]
#[command(name = "tapchat", about = "TapChat CLI")]
pub struct Cli {
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Text)]
    pub output: OutputFormat,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Profile(ProfileCommand),
    Device(DeviceCommand),
    Contact(ContactCommand),
    Conversation(ConversationCommand),
    Message(MessageCommand),
    Group(GroupCommand),
    Sync(SyncCommand),
    Runtime(RuntimeCommand),
}

#[derive(Debug, Args)]
pub struct ProfileCommand {
    #[command(subcommand)]
    pub command: ProfileSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ProfileSubcommand {
    Init {
        #[arg(long)]
        name: String,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        passphrase_stdin: bool,
        #[arg(long)]
        no_keychain: bool,
        #[arg(long)]
        allow_weak_passphrase: bool,
    },
    Show {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    ImportDeployment {
        #[arg(long)]
        profile: Option<PathBuf>,
        bundle_file: PathBuf,
    },
    ExportIdentity {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    List,
    Activate {
        #[arg(long, conflicts_with = "name")]
        profile: Option<PathBuf>,
        #[arg(long, conflicts_with = "profile")]
        name: Option<String>,
    },
    Current,
    Remove {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    Delete {
        #[arg(long)]
        profile: PathBuf,
    },
    Keychain(ProfileKeychainCommand),
}

#[derive(Debug, Args)]
pub struct ProfileKeychainCommand {
    #[command(subcommand)]
    pub command: ProfileKeychainSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ProfileKeychainSubcommand {
    Doctor,
    Cleanup {
        #[arg(long)]
        dry_run: bool,
        #[arg(long, conflicts_with = "dry_run")]
        apply: bool,
    },
}

#[derive(Debug, Args)]
pub struct DeviceCommand {
    #[command(subcommand)]
    pub command: DeviceSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum DeviceSubcommand {
    Create {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        device_name: String,
        #[arg(long)]
        display_name: Option<String>,
        #[arg(long)]
        mnemonic_file: Option<PathBuf>,
    },
    Recover {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        device_name: String,
        #[arg(long)]
        display_name: Option<String>,
        #[arg(long)]
        mnemonic_file: PathBuf,
    },
    Add {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        device_name: String,
        #[arg(long)]
        display_name: Option<String>,
        #[arg(long)]
        mnemonic_file: PathBuf,
    },
    RotateKeyPackage {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    Status {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    /// Register a new device in all existing groups (Phase 8)
    SyncGroups {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        device_id: String,
    },
    Revoke {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        target_device_id: String,
    },
}

#[derive(Debug, Args)]
pub struct ContactCommand {
    #[command(subcommand)]
    pub command: ContactSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ContactSubcommand {
    ImportIdentity {
        #[arg(long)]
        profile: Option<PathBuf>,
        bundle_file: PathBuf,
    },
    Refresh {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        user_id: String,
    },
    Show {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        user_id: String,
    },
    List {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    Requests(ContactRequestsCommand),
    Allowlist(ContactAllowlistCommand),
}

#[derive(Debug, Args)]
pub struct ContactRequestsCommand {
    #[command(subcommand)]
    pub command: ContactRequestsSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ContactRequestsSubcommand {
    List {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    Accept {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        request_id: String,
    },
    Reject {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        request_id: String,
    },
}

#[derive(Debug, Args)]
pub struct ContactAllowlistCommand {
    #[command(subcommand)]
    pub command: ContactAllowlistSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ContactAllowlistSubcommand {
    List {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    Add {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        user_id: String,
    },
    Remove {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        user_id: String,
    },
}

#[derive(Debug, Args)]
pub struct ConversationCommand {
    #[command(subcommand)]
    pub command: ConversationSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ConversationSubcommand {
    CreateDirect {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        peer_user_id: String,
    },
    List {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    Show {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        conversation_id: String,
    },
    Members {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        conversation_id: String,
    },
    Rebuild {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        conversation_id: String,
    },
    Reconcile {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        conversation_id: String,
    },
}

#[derive(Debug, Args)]
pub struct MessageCommand {
    #[command(subcommand)]
    pub command: MessageSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum MessageSubcommand {
    SendText {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        conversation_id: String,
        #[arg(long)]
        text: String,
    },
    SendAttachment {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        conversation_id: String,
        #[arg(long)]
        file: PathBuf,
    },
    DownloadAttachment {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        conversation_id: String,
        #[arg(long)]
        message_id: String,
        #[arg(long)]
        reference: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    List {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        conversation_id: String,
    },
}

#[derive(Debug, Args)]
pub struct GroupCommand {
    #[command(subcommand)]
    pub command: GroupSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum GroupSubcommand {
    /// Create a new group conversation and publish the initial MLS commit
    Create {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        title: String,
        /// Comma-separated list of invitee user ids (at least one required)
        #[arg(long, value_delimiter = ',', num_args = 1..)]
        members: Vec<String>,
    },
    /// List all groups this profile currently participates in
    List {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    /// Show a single group's manifest, members, cursor and recovery state
    Show {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        group_id: String,
    },
    /// Send a text message into the MLS group via the group outbox
    SendText {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        conversation_id: String,
        #[arg(long)]
        text: String,
    },
    /// Send an attachment into the MLS group via the group outbox
    SendAttachment {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        conversation_id: String,
        #[arg(long)]
        file: PathBuf,
    },
    /// Download an attachment previously sent in the group
    DownloadAttachment {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        conversation_id: String,
        #[arg(long)]
        message_id: String,
        #[arg(long)]
        reference: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// List stored messages for the conversation backing this group
    ListMessages {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        conversation_id: String,
    },
    /// Pull new records from the group outbox
    Sync {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        group_id: String,
    },
    /// Leave a group this profile is currently a member of
    Leave {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        group_id: String,
    },
    /// List pending leave requests visible to this owner/admin
    LeaveRequests {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        group_id: String,
    },
    /// Claim and execute a pending leave request (owner/admin only)
    ApproveLeave {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        request_id: String,
    },
    /// Transfer ownership to another active member (owner only)
    TransferOwnership {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        new_owner_user_id: String,
    },
    /// Grant or revoke admin role for a member (owner only)
    SetAdmin {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        user_id: String,
        #[arg(long)]
        admin: bool,
    },
    /// Update group metadata (title / join policy / member invite policy)
    UpdateMetadata {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        title: Option<String>,
        /// One of `closed`, `approval_required`, `open_by_invite`
        #[arg(long)]
        join_policy: Option<String>,
        /// One of `owner_admin_only`, `request_owner_approval`
        #[arg(long)]
        member_invite_policy: Option<String>,
    },
    /// Atomically dissolve a group (owner-only). Issues a single MLS
    /// remove_members commit covering every other active member, appends
    /// a visible `control_group_dissolved` control message, and seals the
    /// group outbox so no further messages can be appended. Dissolves are
    /// irreversible.
    Dissolve {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        group_id: String,
        /// Skip the interactive `[y/N]` confirmation prompt. MUST be
        /// passed explicitly — even in CI / non-interactive environments
        /// the CLI still reads stdin for confirmation when `--yes` is
        /// absent, so automation must supply the flag.
        #[arg(long = "yes", short = 'y')]
        yes: bool,
    },
    Invite(GroupInviteCommand),
    Join(GroupJoinCommand),
    Member(GroupMemberCommand),
}

#[derive(Debug, Args)]
pub struct GroupInviteCommand {
    #[command(subcommand)]
    pub command: GroupInviteSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum GroupInviteSubcommand {
    /// Create a signed invite link usable by join submit
    Create {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        group_id: String,
        /// Seconds from now until the invite expires
        #[arg(long, default_value_t = 3600)]
        expires_in_secs: u64,
        /// Optional maximum number of times the invite may be used
        #[arg(long)]
        max_uses: Option<u64>,
    },
    /// Revoke a previously issued invite link by id
    Revoke {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        invite_id: String,
    },
    /// List invites this profile has issued for a group
    List {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        group_id: String,
    },
}

#[derive(Debug, Args)]
pub struct GroupJoinCommand {
    #[command(subcommand)]
    pub command: GroupJoinSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum GroupJoinSubcommand {
    /// Submit a join request against an invite URL (joiner side)
    Submit {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        invite_url: String,
    },
    /// Import a group from a welcome pickup URL handed out by the owner/admin
    ByPickup {
        #[arg(long)]
        profile: Option<PathBuf>,
        /// Welcome pickup URL (tapchat://welcome-pickup/<base64-json>) or raw descriptor JSON
        #[arg(long)]
        pickup: String,
    },
    /// List pending join requests (owner/admin side)
    List {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        group_id: String,
    },
    /// Approve a pending join request (owner/admin side)
    Approve {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        request_id: String,
    },
    /// Reject a pending join request (owner/admin side)
    Reject {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        request_id: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Poll the server for this join request's status and pick up welcome when available
    Status {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        request_id: String,
    },
}

#[derive(Debug, Args)]
pub struct GroupMemberCommand {
    #[command(subcommand)]
    pub command: GroupMemberSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum GroupMemberSubcommand {
    /// Remove a member from the group (owner/admin only)
    Remove {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        user_id: String,
    },
    /// Register a new device in an existing group (owner/admin only)
    AddDevice {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        device_id: String,
    },
    /// Remove a decommissioned device from an existing group (owner/admin only)
    RemoveDevice {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        group_id: String,
        #[arg(long)]
        device_id: String,
    },
}

#[derive(Debug, Args)]
pub struct SyncCommand {
    #[command(subcommand)]
    pub command: SyncSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum SyncSubcommand {
    Once {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    Foreground {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    RealtimeConnect {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    RealtimeClose {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    Status {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    Head {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        device_id: Option<String>,
    },
}

#[derive(Debug, Args)]
pub struct RuntimeCommand {
    #[command(subcommand)]
    pub command: RuntimeSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum RuntimeSubcommand {
    LocalStart {
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        workspace_root: Option<PathBuf>,
    },
    LocalStop {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    LocalStatus {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    Cloudflare(CloudflareRuntimeCommand),
}

#[derive(Debug, Args)]
pub struct CloudflareRuntimeCommand {
    #[command(subcommand)]
    pub command: CloudflareRuntimeSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum CloudflareRuntimeSubcommand {
    Provision(CloudflareProvisionCommand),
    Status {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    Redeploy {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    RotateSecrets {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    Detach {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
pub struct CloudflareProvisionCommand {
    #[command(subcommand)]
    pub command: CloudflareProvisionSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum CloudflareProvisionSubcommand {
    Auto {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    Custom {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser;

    use super::{
        Cli, CloudflareProvisionCommand, CloudflareProvisionSubcommand, CloudflareRuntimeCommand,
        CloudflareRuntimeSubcommand, Command, OutputFormat, ProfileCommand, ProfileKeychainCommand,
        ProfileKeychainSubcommand, ProfileSubcommand, RuntimeCommand, RuntimeSubcommand,
    };

    #[test]
    fn cli_parses_profile_init() {
        let cli = Cli::parse_from([
            "tapchat",
            "--output",
            "json",
            "profile",
            "init",
            "--name",
            "alice",
            "--root",
            "state/alice",
        ]);
        assert!(matches!(cli.output, OutputFormat::Json));
        match cli.command {
            Command::Profile(ProfileCommand {
                command:
                    ProfileSubcommand::Init {
                        name,
                        allow_weak_passphrase,
                        ..
                    },
            }) => {
                assert_eq!(name, "alice");
                assert!(!allow_weak_passphrase);
            }
            _ => panic!("unexpected command shape"),
        }
    }

    #[test]
    fn cli_parses_profile_init_allow_weak_passphrase() {
        let cli = Cli::parse_from([
            "tapchat",
            "profile",
            "init",
            "--name",
            "alice",
            "--root",
            "state/alice",
            "--allow-weak-passphrase",
        ]);
        match cli.command {
            Command::Profile(ProfileCommand {
                command:
                    ProfileSubcommand::Init {
                        allow_weak_passphrase,
                        ..
                    },
            }) => assert!(allow_weak_passphrase),
            _ => panic!("unexpected command shape"),
        }
    }

    #[test]
    fn cli_parses_profile_activate_by_name() {
        let cli = Cli::parse_from(["tapchat", "profile", "activate", "--name", "alice"]);
        match cli.command {
            Command::Profile(ProfileCommand {
                command: ProfileSubcommand::Activate { name, profile },
            }) => {
                assert_eq!(name.as_deref(), Some("alice"));
                assert!(profile.is_none());
            }
            _ => panic!("unexpected command shape"),
        }
    }

    #[test]
    fn cli_parses_profile_keychain_doctor() {
        let cli = Cli::parse_from(["tapchat", "profile", "keychain", "doctor"]);
        match cli.command {
            Command::Profile(ProfileCommand {
                command:
                    ProfileSubcommand::Keychain(ProfileKeychainCommand {
                        command: ProfileKeychainSubcommand::Doctor,
                    }),
            }) => {}
            _ => panic!("unexpected command shape"),
        }
    }

    #[test]
    fn cli_parses_profile_keychain_cleanup_apply() {
        let cli = Cli::parse_from(["tapchat", "profile", "keychain", "cleanup", "--apply"]);
        match cli.command {
            Command::Profile(ProfileCommand {
                command:
                    ProfileSubcommand::Keychain(ProfileKeychainCommand {
                        command: ProfileKeychainSubcommand::Cleanup { dry_run, apply },
                    }),
            }) => {
                assert!(!dry_run);
                assert!(apply);
            }
            _ => panic!("unexpected command shape"),
        }
    }

    #[test]
    fn cli_parses_profile_delete() {
        let cli = Cli::parse_from(["tapchat", "profile", "delete", "--profile", "state/alice"]);
        match cli.command {
            Command::Profile(ProfileCommand {
                command: ProfileSubcommand::Delete { profile },
            }) => assert_eq!(profile, PathBuf::from("state/alice")),
            _ => panic!("unexpected command shape"),
        }
    }

    #[test]
    fn cli_parses_runtime_cloudflare_provision_auto() {
        let cli = Cli::parse_from([
            "tapchat",
            "runtime",
            "cloudflare",
            "provision",
            "auto",
            "--profile",
            "state/alice",
        ]);
        match cli.command {
            Command::Runtime(RuntimeCommand {
                command:
                    RuntimeSubcommand::Cloudflare(CloudflareRuntimeCommand {
                        command:
                            CloudflareRuntimeSubcommand::Provision(CloudflareProvisionCommand {
                                command: CloudflareProvisionSubcommand::Auto { profile },
                            }),
                    }),
            }) => assert_eq!(profile, Some(PathBuf::from("state/alice"))),
            _ => panic!("unexpected command shape"),
        }
    }
}
