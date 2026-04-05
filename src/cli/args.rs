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
    },
    Show {
        #[arg(long)]
        profile: PathBuf,
    },
    ImportDeployment {
        #[arg(long)]
        profile: PathBuf,
        bundle_file: PathBuf,
    },
    ExportIdentity {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
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
        profile: PathBuf,
        #[arg(long)]
        device_name: String,
        #[arg(long)]
        mnemonic_file: Option<PathBuf>,
    },
    Recover {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        device_name: String,
        #[arg(long)]
        mnemonic_file: PathBuf,
    },
    Add {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        device_name: String,
        #[arg(long)]
        mnemonic_file: PathBuf,
    },
    RotateKeyPackage {
        #[arg(long)]
        profile: PathBuf,
    },
    Status {
        #[arg(long)]
        profile: PathBuf,
    },
    Revoke {
        #[arg(long)]
        profile: PathBuf,
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
        profile: PathBuf,
        bundle_file: PathBuf,
    },
    Refresh {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        user_id: String,
    },
    Show {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        user_id: String,
    },
    List {
        #[arg(long)]
        profile: PathBuf,
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
        profile: PathBuf,
    },
    Accept {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        request_id: String,
    },
    Reject {
        #[arg(long)]
        profile: PathBuf,
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
        profile: PathBuf,
    },
    Add {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        user_id: String,
    },
    Remove {
        #[arg(long)]
        profile: PathBuf,
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
        profile: PathBuf,
        #[arg(long)]
        peer_user_id: String,
    },
    List {
        #[arg(long)]
        profile: PathBuf,
    },
    Show {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        conversation_id: String,
    },
    Members {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        conversation_id: String,
    },
    Rebuild {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        conversation_id: String,
    },
    Reconcile {
        #[arg(long)]
        profile: PathBuf,
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
        profile: PathBuf,
        #[arg(long)]
        conversation_id: String,
        #[arg(long)]
        text: String,
    },
    SendAttachment {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        conversation_id: String,
        #[arg(long)]
        file: PathBuf,
    },
    DownloadAttachment {
        #[arg(long)]
        profile: PathBuf,
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
        profile: PathBuf,
        #[arg(long)]
        conversation_id: String,
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
        profile: PathBuf,
    },
    Foreground {
        #[arg(long)]
        profile: PathBuf,
    },
    RealtimeConnect {
        #[arg(long)]
        profile: PathBuf,
    },
    RealtimeClose {
        #[arg(long)]
        profile: PathBuf,
    },
    Status {
        #[arg(long)]
        profile: PathBuf,
    },
    Head {
        #[arg(long)]
        profile: PathBuf,
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
        profile: PathBuf,
        #[arg(long)]
        workspace_root: Option<PathBuf>,
    },
    LocalStop {
        #[arg(long)]
        profile: PathBuf,
    },
    LocalStatus {
        #[arg(long)]
        profile: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Command, OutputFormat, ProfileCommand, ProfileSubcommand};

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
                command: ProfileSubcommand::Init { name, .. },
            }) => assert_eq!(name, "alice"),
            _ => panic!("unexpected command shape"),
        }
    }
}
