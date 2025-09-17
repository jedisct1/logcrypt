use crate::cli::{BatchOperation, OutputFormat};
use crate::{ipcrypt_module, uricrypt_module};
use anyhow::{anyhow, Result};
use rand::{rng, Rng};
use serde_json::json;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};

pub fn output_result(result: &str, format: Option<&OutputFormat>) -> Result<()> {
    match format {
        Some(OutputFormat::Json) | None if std::env::var("JSON_OUTPUT").is_ok() => {
            let output = json!({
                "result": result,
                "success": true
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        Some(OutputFormat::Plain) | None => {
            println!("{}", result);
        }
        Some(OutputFormat::Json) => {
            let output = json!({
                "result": result,
                "success": true
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
    }
    Ok(())
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

        let result = match operation {
            BatchOperation::EncryptIp => match ipcrypt_module::encrypt_ip(line, key) {
                Ok(encrypted) => json!({
                    "input": line,
                    "output": encrypted,
                    "operation": "encrypt_ip",
                    "success": true
                }),
                Err(e) => {
                    errors.push(format!("Line {}: {}", line_num + 1, e));
                    json!({
                        "input": line,
                        "error": e.to_string(),
                        "operation": "encrypt_ip",
                        "success": false
                    })
                }
            },
            BatchOperation::DecryptIp => match ipcrypt_module::decrypt_ip(line, key) {
                Ok(decrypted) => json!({
                    "input": line,
                    "output": decrypted,
                    "operation": "decrypt_ip",
                    "success": true
                }),
                Err(e) => {
                    errors.push(format!("Line {}: {}", line_num + 1, e));
                    json!({
                        "input": line,
                        "error": e.to_string(),
                        "operation": "decrypt_ip",
                        "success": false
                    })
                }
            },
            BatchOperation::EncryptUri => match uricrypt_module::encrypt_uri(line, key) {
                Ok(encrypted) => json!({
                    "input": line,
                    "output": encrypted,
                    "operation": "encrypt_uri",
                    "success": true
                }),
                Err(e) => {
                    errors.push(format!("Line {}: {}", line_num + 1, e));
                    json!({
                        "input": line,
                        "error": e.to_string(),
                        "operation": "encrypt_uri",
                        "success": false
                    })
                }
            },
            BatchOperation::DecryptUri => match uricrypt_module::decrypt_uri(line, key) {
                Ok(decrypted) => json!({
                    "input": line,
                    "output": decrypted,
                    "operation": "decrypt_uri",
                    "success": true
                }),
                Err(e) => {
                    errors.push(format!("Line {}: {}", line_num + 1, e));
                    json!({
                        "input": line,
                        "error": e.to_string(),
                        "operation": "decrypt_uri",
                        "success": false
                    })
                }
            },
        };

        results.push(result);
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
            anyhow!(
                "No key provided. Either use --key flag or set LOGCRYPT_KEY environment variable"
            )
        })?,
    };

    let key_bytes = hex::decode(&key_str).map_err(|e| anyhow!("Invalid hex key: {}", e))?;

    // Validate key length
    if key_bytes.len() != 32 {
        return Err(anyhow!(
            "Key must be exactly 32 bytes (64 hex characters), got {} bytes",
            key_bytes.len()
        ));
    }

    // Check if the two halves are different (required for IPCrypt-PFX)
    let first_half = &key_bytes[0..16];
    let second_half = &key_bytes[16..32];
    if first_half == second_half {
        return Err(anyhow!(
            "Invalid key: The two 16-byte halves of the key must be different for security.\n\
            Your key has identical halves. Please generate a new key using:\n\
            logcrypt generate-key --ensure-different-halves"
        ));
    }

    Ok(key_bytes)
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
