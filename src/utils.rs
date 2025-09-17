//! Utility functions for LogCrypt
//!
//! This module provides common utilities for:
//! - Output formatting (plain text and JSON)
//! - Batch processing operations
//! - Key management and validation
//! - File I/O operations

use crate::cli::{BatchOperation, OutputFormat};
use crate::{ipcrypt_module, uricrypt_module};
use anyhow::{anyhow, Result};
use rand::{rng, Rng};
use serde_json::{json, Value};
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};

pub fn output_result(result: &str, format: Option<&OutputFormat>) -> Result<()> {
    let should_output_json = format.is_some_and(|f| matches!(f, OutputFormat::Json))
        || std::env::var("JSON_OUTPUT").is_ok();

    if should_output_json {
        let output = json!({
            "result": result,
            "success": true
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("{}", result);
    }
    Ok(())
}

fn create_batch_result(
    input: &str,
    output: Result<String>,
    operation_name: &str,
    line_num: usize,
) -> (Value, Option<String>) {
    match output {
        Ok(result) => (
            json!({
                "input": input,
                "output": result,
                "operation": operation_name,
                "success": true
            }),
            None,
        ),
        Err(e) => {
            let error_msg = Some(format!("Line {}: {}", line_num + 1, e));
            let result = json!({
                "input": input,
                "error": e.to_string(),
                "operation": operation_name,
                "success": false
            });
            (result, error_msg)
        }
    }
}

pub fn process_batch(
    input_path: &str,
    output_path: Option<&String>,
    operation: &BatchOperation,
    key: &[u8],
) -> Result<()> {
    let input_file =
        File::open(input_path).map_err(|e| anyhow!("Failed to open input file: {}", e))?;
    let reader = BufReader::new(input_file);

    let mut results = Vec::new();
    let mut errors = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| anyhow!("Failed to read line {}: {}", line_num + 1, e))?;
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (operation_func, operation_name) = match operation {
            BatchOperation::EncryptIp => (
                ipcrypt_module::encrypt_ip as fn(&str, &[u8]) -> Result<String>,
                "encrypt_ip",
            ),
            BatchOperation::DecryptIp => (
                ipcrypt_module::decrypt_ip as fn(&str, &[u8]) -> Result<String>,
                "decrypt_ip",
            ),
            BatchOperation::EncryptUri => (
                uricrypt_module::encrypt_uri as fn(&str, &[u8]) -> Result<String>,
                "encrypt_uri",
            ),
            BatchOperation::DecryptUri => (
                uricrypt_module::decrypt_uri as fn(&str, &[u8]) -> Result<String>,
                "decrypt_uri",
            ),
        };

        let (result, error) =
            create_batch_result(line, operation_func(line, key), operation_name, line_num);
        results.push(result);
        if let Some(err) = error {
            errors.push(err);
        }
    }

    let output = json!({
        "results": results,
        "total": results.len(),
        "errors": errors.len(),
        "error_messages": errors
    });

    match output_path {
        Some(path) => {
            let mut file =
                File::create(path).map_err(|e| anyhow!("Failed to create output file: {}", e))?;
            file.write_all(serde_json::to_string_pretty(&output)?.as_bytes())
                .map_err(|e| anyhow!("Failed to write output file: {}", e))?;
            println!("Batch processing complete. Results written to: {}", path);
        }
        None => {
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
    }

    if !errors.is_empty() {
        eprintln!(
            "\nWarning: {} errors occurred during processing",
            errors.len()
        );
    }

    Ok(())
}

pub fn get_key_from_env_or_arg(key_arg: &Option<String>) -> Result<Vec<u8>> {
    let key_str = match key_arg {
        Some(key) => key.clone(),
        None => env::var("LOGCRYPT_KEY").map_err(|_| {
            anyhow::anyhow!(
                "No key provided. Either use --key flag or set LOGCRYPT_KEY environment variable"
            )
        })?,
    };

    let key_bytes = hex::decode(&key_str).map_err(|e| anyhow::anyhow!("Invalid hex key: {}", e))?;

    validate_key(&key_bytes)?;

    Ok(key_bytes)
}

fn validate_key(key: &[u8]) -> Result<()> {
    // Validate key length
    if key.len() != 32 {
        return Err(anyhow::anyhow!(
            "Key must be exactly 32 bytes (64 hex characters), got {} bytes",
            key.len()
        ));
    }

    // Check if the two halves are different (required for IPCrypt-PFX)
    let (first_half, second_half) = key.split_at(16);
    if first_half == second_half {
        return Err(anyhow::anyhow!(
            "Invalid key: The two 16-byte halves of the key must be different for security.\n\
            Your key has identical halves. Please generate a new key using:\n\
            logcrypt generate-key --ensure-different-halves"
        ));
    }

    Ok(())
}

pub fn generate_secure_key(_ensure_different_halves: bool) -> Result<String> {
    let mut rng = rng();
    let mut key = [0u8; 32];

    // Always generate keys with different halves for safety
    // The ensure_different_halves parameter is kept for backward compatibility
    // but we always ensure different halves now
    loop {
        rng.fill(&mut key);

        // Check if the two 16-byte halves are different
        let first_half = &key[0..16];
        let second_half = &key[16..32];

        if first_half != second_half {
            break;
        }
        // If halves are the same (extremely unlikely), generate again
    }

    Ok(hex::encode(key))
}

pub fn output_key(key: &str, format: Option<&OutputFormat>) -> Result<()> {
    match format {
        Some(OutputFormat::Json) => {
            let output = json!({
                "key": key,
                "bits": 256,
                "bytes": 32,
                "success": true
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        Some(OutputFormat::Plain) | None => {
            println!("{}", key);
        }
    }
    Ok(())
}

pub fn read_file_sample(path: &str, max_lines: usize) -> Result<Vec<String>> {
    let file = File::open(path).map_err(|e| anyhow!("Failed to open file: {}", e))?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();

    for (i, line) in reader.lines().enumerate() {
        if i >= max_lines {
            break;
        }
        lines.push(line.map_err(|e| anyhow!("Failed to read line {}: {}", i + 1, e))?);
    }

    Ok(lines)
}
