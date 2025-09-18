mod cli;
mod ipcrypt_module;
mod log_parser;
mod uricrypt_module;
mod utils;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands, LogOperation};
use log_parser::{LogParser, ParseOperation, ParseOptions};

fn process_single_item(
    input: &str,
    key: &Option<String>,
    output: &Option<cli::OutputFormat>,
    operation: fn(&str, &[u8]) -> Result<String>,
    error_msg: &str,
) -> Result<()> {
    let key_bytes = utils::get_key_from_env_or_arg(key)?;
    let result =
        operation(input, &key_bytes).map_err(|e| anyhow::anyhow!("{}: {}", error_msg, e))?;
    utils::output_result(&result, output.as_ref())?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::EncryptIp { ip, key, output } => process_single_item(
            ip,
            key,
            output,
            ipcrypt_module::encrypt_ip,
            "Failed to encrypt IP address",
        )?,
        Commands::DecryptIp { ip, key, output } => process_single_item(
            ip,
            key,
            output,
            ipcrypt_module::decrypt_ip,
            "Failed to decrypt IP address",
        )?,
        Commands::EncryptUri { uri, key, output } => process_single_item(
            uri,
            key,
            output,
            uricrypt_module::encrypt_uri,
            "Failed to encrypt URI",
        )?,
        Commands::DecryptUri { uri, key, output } => process_single_item(
            uri,
            key,
            output,
            uricrypt_module::decrypt_uri,
            "Failed to decrypt URI",
        )?,
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
            ip_only,
            uri_only,
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
                process_ips: !*uri_only,  // Process IPs unless --uri-only is set
                process_uris: !*ip_only,  // Process URIs unless --ip-only is set
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
