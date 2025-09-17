mod cli;
mod ipcrypt_module;
mod log_parser;
mod uricrypt_module;
mod utils;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands, LogOperation};
use log_parser::{LogParser, ParseOperation, ParseOptions};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::EncryptIp { ip, key, output } => {
            let key_bytes = utils::get_key_from_env_or_arg(key)?;
            let encrypted = ipcrypt_module::encrypt_ip(ip, &key_bytes)?;
            utils::output_result(&encrypted, output.as_ref())?;
        }
        Commands::DecryptIp { ip, key, output } => {
            let key_bytes = utils::get_key_from_env_or_arg(key)?;
            let decrypted = ipcrypt_module::decrypt_ip(ip, &key_bytes)?;
            utils::output_result(&decrypted, output.as_ref())?;
        }
        Commands::EncryptUri { uri, key, output } => {
            let key_bytes = utils::get_key_from_env_or_arg(key)?;
            let encrypted = uricrypt_module::encrypt_uri(uri, &key_bytes)?;
            utils::output_result(&encrypted, output.as_ref())?;
        }
        Commands::DecryptUri { uri, key, output } => {
            let key_bytes = utils::get_key_from_env_or_arg(key)?;
            let decrypted = uricrypt_module::decrypt_uri(uri, &key_bytes)?;
            utils::output_result(&decrypted, output.as_ref())?;
        }
        Commands::Batch {
            input,
            output,
            operation,
            key,
        } => {
            let key_bytes = utils::get_key_from_env_or_arg(key)?;
            utils::process_batch(input, output.as_ref(), operation, &key_bytes)?;
        }
        Commands::GenerateKey {
            output,
            ensure_different_halves,
        } => {
            let key = utils::generate_secure_key(*ensure_different_halves)?;
            utils::output_key(&key, output.as_ref())?;
        }
        Commands::ParseLogs {
            input,
            output,
            operation,
            key,
            format,
            dry_run,
        } => {
            let key = if matches!(operation, LogOperation::Encrypt | LogOperation::Decrypt) {
                Some(utils::get_key_from_env_or_arg(key)?)
            } else {
                None
            };

            let parse_operation = match operation {
                LogOperation::Encrypt => ParseOperation::Encrypt,
                LogOperation::Decrypt => ParseOperation::Decrypt,
                LogOperation::Redact => ParseOperation::Redact,
            };

            let options = ParseOptions {
                operation: parse_operation,
                key,
                format: format.as_ref().and_then(|f| parse_log_format(f)),
                dry_run: *dry_run,
            };

            let sample_lines = utils::read_file_sample(input, 50)?;
            let parser = LogParser::detect_and_new(options, sample_lines)?;

            println!("Detected log format: {}", parser.get_format().name());
            parser.process_file(input, output.as_deref())?;
        }
    }

    Ok(())
}

fn parse_log_format(format: &str) -> Option<log_parser::formats::LogFormat> {
    use log_parser::formats::LogFormat;
    match format.to_lowercase().as_str() {
        "apache" => Some(LogFormat::ApacheCombined),
        "clf" => Some(LogFormat::CommonLog),
        "json" => Some(LogFormat::Json),
        "syslog" => Some(LogFormat::Syslog),
        _ => None,
    }
}
