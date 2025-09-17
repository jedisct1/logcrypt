use super::{LogLineParser, ParsedLogLine};
use crate::log_parser::patterns::{find_all_ips, find_all_uris};
use anyhow::Result;
use serde_json::Value;

pub struct JsonLogParser;

impl LogLineParser for JsonLogParser {
    fn parse_line(&self, line: &str) -> Result<ParsedLogLine> {
        let mut ip_positions = Vec::new();
        let mut uri_positions = Vec::new();

        if let Ok(json) = serde_json::from_str::<Value>(line) {
            find_json_ips_and_uris(&json, line, 0, &mut ip_positions, &mut uri_positions);
        }

        let all_ips = find_all_ips(line);
        for ip_match in all_ips {
            let already_found = ip_positions
                .iter()
                .any(|(start, end, _)| ip_match.start >= *start && ip_match.end <= *end);
            if !already_found {
                ip_positions.push((ip_match.start, ip_match.end, ip_match.value));
            }
        }

        let all_uris = find_all_uris(line);
        for uri_match in all_uris {
            let already_found = uri_positions
                .iter()
                .any(|(start, end, _)| uri_match.start >= *start && uri_match.end <= *end);
            if !already_found {
                uri_positions.push((uri_match.start, uri_match.end, uri_match.value));
            }
        }

        Ok(ParsedLogLine {
            original: line.to_string(),
            ip_positions,
            uri_positions,
        })
    }
}

fn find_json_ips_and_uris(
    value: &Value,
    original_line: &str,
    _offset: usize,
    ip_positions: &mut Vec<(usize, usize, String)>,
    uri_positions: &mut Vec<(usize, usize, String)>,
) {
    if let Value::Object(map) = value {
        for (key, val) in map {
            let key_lower = key.to_lowercase();

            if let Value::String(s) = val {
                if key_lower.contains("ip")
                    || key_lower.contains("address")
                    || key_lower.contains("client")
                    || key_lower.contains("remote")
                {
                    if let Some(pos) = original_line.find(s.as_str()) {
                        ip_positions.push((pos, pos + s.len(), s.clone()));
                    }
                }

                if key_lower.contains("url")
                    || key_lower.contains("uri")
                    || key_lower.contains("path")
                    || key_lower.contains("endpoint")
                    || key_lower.contains("referer")
                    || key_lower.contains("referrer")
                {
                    if let Some(pos) = original_line.find(s.as_str()) {
                        uri_positions.push((pos, pos + s.len(), s.clone()));
                    }
                }
            }
        }
    }
}
