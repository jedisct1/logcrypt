use super::detector::detect_format;
use super::formats::{
    apache::ApacheLogParser, bunnycdn::BunnyCDNLogParser, generic::GenericLogParser,
    json::JsonLogParser, LogFormat, LogLineParser,
};
use crate::ipcrypt_module::IpCipher;
use crate::uricrypt_module;
use anyhow::Result;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};

#[derive(Debug, Clone, Copy)]
pub enum ParseOperation {
    Encrypt,
    Decrypt,
    Redact,
}

#[derive(Debug, Clone)]
pub struct ParseOptions {
    pub operation: ParseOperation,
    pub key: Option<Vec<u8>>,
    pub format: Option<LogFormat>,
    pub dry_run: bool,
    pub process_ips: bool,
    pub process_uris: bool,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            operation: ParseOperation::Redact,
            key: None,
            format: None,
            dry_run: false,
            process_ips: true,
            process_uris: true,
        }
    }
}

pub struct LogParser {
    options: ParseOptions,
    format: LogFormat,
    parser: Box<dyn LogLineParser>,
    ip_cipher: Option<IpCipher>,
}

impl LogParser {
    pub fn detect_and_new(options: ParseOptions, sample_lines: Vec<String>) -> Result<Self> {
        let detection = detect_format(&sample_lines);
        let format = if let Some(forced) = options.format.clone() {
            forced
        } else {
            detection.format
        };

        let parser = Self::get_parser(&format);

        // Pre-create cipher instances for better performance
        let ip_cipher = if options.process_ips {
            options.key.as_ref().map(|k| IpCipher::new(k)).transpose()?
        } else {
            None
        };

        Ok(Self {
            options,
            format,
            parser,
            ip_cipher,
        })
    }

    fn get_parser(format: &LogFormat) -> Box<dyn LogLineParser> {
        match format {
            LogFormat::ApacheCombined | LogFormat::CommonLog => Box::new(ApacheLogParser),
            LogFormat::BunnyCDN => Box::new(BunnyCDNLogParser),
            LogFormat::Json => Box::new(JsonLogParser),
            _ => Box::new(GenericLogParser),
        }
    }

    pub fn process_file(&self, input_path: &str, output_path: Option<&str>) -> Result<()> {
        let file = File::open(input_path)?;
        let reader = BufReader::new(file);

        let mut output: Box<dyn Write> = if let Some(path) = output_path {
            Box::new(BufWriter::new(File::create(path)?))
        } else {
            Box::new(BufWriter::new(std::io::stdout()))
        };

        if self.options.dry_run {
            println!("DRY RUN - Format detected: {}", self.format.name());
            println!("Changes that would be made:");
            println!("----------------------------");
        }

        for line in reader.lines() {
            let line = line?;
            // If processing a line fails, use the original line
            let processed = match self.process_line(&line) {
                Ok(result) => result,
                Err(_) => line.clone(),
            };

            if self.options.dry_run {
                if line != processed {
                    println!("Original: {}", line);
                    println!("Modified: {}", processed);
                    println!();
                }
            } else {
                writeln!(output, "{}", processed)?;
            }
        }

        Ok(())
    }

    pub fn process_line(&self, line: &str) -> Result<String> {
        if line.trim().is_empty() {
            return Ok(line.to_string());
        }

        let parsed = self.parser.parse_line(line)?;
        let mut result = parsed.original.clone();

        let mut replacements: Vec<(usize, usize, String)> = Vec::new();

        if self.options.process_ips {
            for (start, end, value) in &parsed.ip_positions {
                let replacement = self.process_ip(value)?;
                replacements.push((*start, *end, replacement));
            }
        }

        if self.options.process_uris {
            for (start, end, value) in &parsed.uri_positions {
                let replacement = self.process_uri(value)?;
                replacements.push((*start, *end, replacement));
            }
        }

        replacements.sort_by(|a, b| b.0.cmp(&a.0));

        for (start, end, replacement) in replacements {
            let before = &result[..start];
            let after = &result[end..];
            result = format!("{}{}{}", before, replacement, after);
        }

        Ok(result)
    }

    fn process_ip(&self, ip: &str) -> Result<String> {
        match self.options.operation {
            ParseOperation::Encrypt => {
                if let Some(cipher) = &self.ip_cipher {
                    cipher.encrypt(ip)
                } else {
                    Ok("[ENCRYPTED_IP]".to_string())
                }
            }
            ParseOperation::Decrypt => {
                if let Some(cipher) = &self.ip_cipher {
                    // If decryption fails, return the original value
                    match cipher.decrypt(ip) {
                        Ok(decrypted) => Ok(decrypted),
                        Err(_) => Ok(ip.to_string()),
                    }
                } else {
                    Ok(ip.to_string())
                }
            }
            ParseOperation::Redact => Ok("[REDACTED_IP]".to_string()),
        }
    }

    fn process_uri(&self, uri: &str) -> Result<String> {
        match self.options.operation {
            ParseOperation::Encrypt => {
                if let Some(key) = &self.options.key {
                    uricrypt_module::encrypt_uri(uri, key)
                } else {
                    Ok("[ENCRYPTED_URI]".to_string())
                }
            }
            ParseOperation::Decrypt => {
                if let Some(key) = &self.options.key {
                    // If decryption fails, return the original value
                    match uricrypt_module::decrypt_uri(uri, key) {
                        Ok(decrypted) => Ok(decrypted),
                        Err(_) => Ok(uri.to_string()),
                    }
                } else {
                    Ok(uri.to_string())
                }
            }
            ParseOperation::Redact => Ok("[REDACTED_URI]".to_string()),
        }
    }

    pub fn get_format(&self) -> &LogFormat {
        &self.format
    }
}
