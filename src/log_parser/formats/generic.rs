use super::{LogLineParser, ParsedLogLine};
use crate::log_parser::patterns::{find_all_ips, find_all_uris};
use anyhow::Result;

pub struct GenericLogParser;

impl LogLineParser for GenericLogParser {
    fn parse_line(&self, line: &str) -> Result<ParsedLogLine> {
        let mut ip_positions = Vec::new();
        let mut uri_positions = Vec::new();

        let all_ips = find_all_ips(line);
        for ip_match in all_ips {
            ip_positions.push((ip_match.start, ip_match.end, ip_match.value));
        }

        let all_uris = find_all_uris(line);
        for uri_match in all_uris {
            uri_positions.push((uri_match.start, uri_match.end, uri_match.value));
        }

        Ok(ParsedLogLine {
            original: line.to_string(),
            ip_positions,
            uri_positions,
        })
    }
}
