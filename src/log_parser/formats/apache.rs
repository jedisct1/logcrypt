use super::{LogLineParser, ParsedLogLine};
use crate::log_parser::patterns::{find_all_ips, find_all_uris, APACHE_LOG_PATTERN};
use anyhow::Result;

pub struct ApacheLogParser;

impl LogLineParser for ApacheLogParser {
    fn parse_line(&self, line: &str) -> Result<ParsedLogLine> {
        let mut ip_positions = Vec::new();
        let mut uri_positions = Vec::new();

        if let Some(captures) = APACHE_LOG_PATTERN.captures(line) {
            if let Some(ip_match) = captures.get(1) {
                ip_positions.push((
                    ip_match.start(),
                    ip_match.end(),
                    ip_match.as_str().to_string(),
                ));
            }

            if let Some(request_match) = captures.get(3) {
                let request_str = request_match.as_str();
                let parts: Vec<&str> = request_str.split_whitespace().collect();
                if parts.len() >= 2 {
                    let uri = parts[1];
                    let uri_start = request_match.start() + request_str.find(uri).unwrap_or(0);
                    let uri_end = uri_start + uri.len();
                    uri_positions.push((uri_start, uri_end, uri.to_string()));

                    // Note: We could detect embedded URLs within query strings here,
                    // but since the entire URI (including query string) is already being
                    // redacted/encrypted as one unit, detecting embedded URLs separately
                    // would create overlapping replacements. The entire URI with its
                    // query string (including any embedded URLs) will be processed as one unit.
                }
            }

            if let Some(referer_match) = captures.get(6) {
                let referer = referer_match.as_str();
                if referer != "-"
                    && (referer.starts_with("http://") || referer.starts_with("https://"))
                {
                    uri_positions.push((
                        referer_match.start(),
                        referer_match.end(),
                        referer.to_string(),
                    ));
                }
            }
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
