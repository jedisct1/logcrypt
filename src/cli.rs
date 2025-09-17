use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "logcrypt")]
#[command(author, version, about = "Encrypt and decrypt IP addresses and URIs", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Encrypt an IP address")]
    EncryptIp {
        #[arg(help = "IP address to encrypt (IPv4 or IPv6)")]
        ip: String,

        #[arg(
            short,
            long,
            help = "Encryption key (hex encoded, 32 bytes). Can also be set via LOGCRYPT_KEY env var"
        )]
        key: Option<String>,

        #[arg(short, long, value_enum, help = "Output format")]
        output: Option<OutputFormat>,
    },

    #[command(about = "Decrypt an encrypted IP address")]
    DecryptIp {
        #[arg(help = "Encrypted IP address to decrypt")]
        ip: String,

        #[arg(
            short,
            long,
            help = "Decryption key (hex encoded, 32 bytes). Can also be set via LOGCRYPT_KEY env var"
        )]
        key: Option<String>,

        #[arg(short, long, value_enum, help = "Output format")]
        output: Option<OutputFormat>,
    },

    #[command(about = "Encrypt a URI")]
    EncryptUri {
        #[arg(help = "URI to encrypt")]
        uri: String,

        #[arg(
            short,
            long,
            help = "Encryption key (hex encoded, 32 bytes). Can also be set via LOGCRYPT_KEY env var"
        )]
        key: Option<String>,

        #[arg(short, long, value_enum, help = "Output format")]
        output: Option<OutputFormat>,
    },

    #[command(about = "Decrypt an encrypted URI")]
    DecryptUri {
        #[arg(help = "Encrypted URI to decrypt")]
        uri: String,

        #[arg(
            short,
            long,
            help = "Decryption key (hex encoded, 32 bytes). Can also be set via LOGCRYPT_KEY env var"
        )]
        key: Option<String>,

        #[arg(short, long, value_enum, help = "Output format")]
        output: Option<OutputFormat>,
    },

    #[command(about = "Process multiple items from a file")]
    Batch {
        #[arg(short, long, help = "Input file path")]
        input: String,

        #[arg(short, long, help = "Output file path")]
        output: Option<String>,

        #[arg(short = 'p', long, value_enum, help = "Operation to perform")]
        operation: BatchOperation,

        #[arg(
            short,
            long,
            help = "Key for encryption/decryption (hex encoded). Can also be set via LOGCRYPT_KEY env var"
        )]
        key: Option<String>,
    },

    #[command(about = "Generate a cryptographically secure 256-bit key")]
    GenerateKey {
        #[arg(short, long, value_enum, help = "Output format")]
        output: Option<OutputFormat>,

        #[arg(
            long,
            help = "Ensure key halves are different (required for IPCrypt-PFX)"
        )]
        ensure_different_halves: bool,
    },

    #[command(about = "Parse log files and encrypt/decrypt/redact IP addresses and URIs")]
    ParseLogs {
        #[arg(help = "Input log file path")]
        input: String,

        #[arg(short, long, help = "Output file path (default: stdout)")]
        output: Option<String>,

        #[arg(short = 'p', long, value_enum, help = "Operation to perform")]
        operation: LogOperation,

        #[arg(
            short,
            long,
            help = "Key for encryption/decryption (hex encoded). Can also be set via LOGCRYPT_KEY env var"
        )]
        key: Option<String>,

        #[arg(long, help = "Force specific log format (auto-detect by default)")]
        format: Option<String>,

        #[arg(long, help = "Show what would be changed without making changes")]
        dry_run: bool,
    },
}

#[derive(Clone, Copy, ValueEnum, Serialize, Deserialize)]
pub enum OutputFormat {
    Plain,
    Json,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum BatchOperation {
    EncryptIp,
    DecryptIp,
    EncryptUri,
    DecryptUri,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum LogOperation {
    Encrypt,
    Decrypt,
    Redact,
}
