use super::{LogLineParser, ParsedLogLine};
use crate::log_parser::patterns::{find_all_ips, find_all_uris};
use anyhow::Result;
use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref BUNNYCDN_LOG_PATTERN: Regex = Regex::new(
        r"^([A-Z]+)\|(\d+)\|(\d+)\|(\d+)\|(\d+)\|([0-9.:]+)\|([^|]*)\|([^|]+)\|([^|]*)\|([^|]+)\|([^|]+)\|([A-Z]{2})$"
    )
    .unwrap();
}

pub struct BunnyCDNLogParser;

impl LogLineParser for BunnyCDNLogParser {
    fn parse_line(&self, line: &str) -> Result<ParsedLogLine> {
        let mut ip_positions = Vec::new();
        let mut uri_positions = Vec::new();

        // BunnyCDN logs are pipe-delimited with fields:
        // cache_status|http_status|timestamp|response_time|bytes|client_ip|unknown|url|edge_location|user_agent|request_id|country_code

        let parts: Vec<&str> = line.split('|').collect();

        if parts.len() >= 12 {
            // Client IP is at index 5
            if let Some(ip_field) = parts.get(5) {
                let ip = ip_field.trim();
                if !ip.is_empty() && ip != "-" {
                    // Find the position of this IP in the original line
                    if let Some(pos) = line.find(ip) {
                        ip_positions.push((pos, pos + ip.len(), ip.to_string()));
                    }
                }
            }

            // URL is at index 7
            if let Some(url_field) = parts.get(7) {
                let url = url_field.trim();
                if !url.is_empty() && url != "-" {
                    // Find the position of this URL in the original line
                    if let Some(pos) = line.find(url) {
                        uri_positions.push((pos, pos + url.len(), url.to_string()));
                    }
                }
            }
        }

        // Also check for any other IPs in the line (e.g., in other fields)
        for ip_match in find_all_ips(line) {
            // Avoid duplicates
            if !ip_positions.iter().any(|(s, _, _)| *s == ip_match.start) {
                ip_positions.push((ip_match.start, ip_match.end, ip_match.value));
            }
        }

        // Also check for any other URIs in the line
        for uri_match in find_all_uris(line) {
            // Avoid duplicates
            if !uri_positions.iter().any(|(s, _, _)| *s == uri_match.start) {
                uri_positions.push((uri_match.start, uri_match.end, uri_match.value));
            }
        }

        Ok(ParsedLogLine {
            original: line.to_string(),
            ip_positions,
            uri_positions,
        })
    }

    fn confidence(&self, line: &str) -> f32 {
        // Check if the line matches the BunnyCDN format
        let parts: Vec<&str> = line.split('|').collect();

        // BunnyCDN logs typically have 12 pipe-delimited fields
        if parts.len() != 12 {
            return 0.0;
        }

        let mut score = 0.0;

        // Check cache status (HIT, MISS, etc.)
        if let Some(cache_status) = parts.first() {
            if matches!(
                cache_status.trim(),
                "HIT" | "MISS" | "STALE" | "UPDATING" | "EXPIRED"
            ) {
                score += 0.2;
            }
        }

        // Check HTTP status code
        if let Some(status) = parts.get(1) {
            if status
                .trim()
                .parse::<u16>()
                .is_ok_and(|s| (100..600).contains(&s))
            {
                score += 0.2;
            }
        }

        // Check timestamp (Unix timestamp in milliseconds)
        if let Some(timestamp) = parts.get(2) {
            if timestamp
                .trim()
                .parse::<u64>()
                .is_ok_and(|t| t > 1000000000000 && t < 2000000000000)
            {
                score += 0.15;
            }
        }

        // Check for IP address in field 5
        if let Some(ip) = parts.get(5) {
            if !find_all_ips(ip).is_empty() {
                score += 0.15;
            }
        }

        // Check for URL in field 7
        if let Some(url) = parts.get(7) {
            if url.starts_with("http://") || url.starts_with("https://") {
                score += 0.15;
            }
        }

        // Check for country code in last field
        if let Some(country) = parts.get(11) {
            let country = country.trim();
            if country.len() == 2 && country.chars().all(|c| c.is_ascii_uppercase()) {
                score += 0.15;
            }
        }

        score
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bunnycdn_log_parsing() {
        let parser = BunnyCDNLogParser;
        let line = "HIT|200|1758146509371|164848|4029805|172.56.107.128|-|https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md|WA|curl/7.74.0|8af30092aac1a36890efd0c82857cb1b|US";

        let result = parser.parse_line(line).unwrap();

        // Should detect the IP address
        assert_eq!(result.ip_positions.len(), 1);
        assert_eq!(result.ip_positions[0].2, "172.56.107.128");

        // Should detect the URL
        assert_eq!(result.uri_positions.len(), 1);
        assert_eq!(
            result.uri_positions[0].2,
            "https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md"
        );
    }

    #[test]
    fn test_bunnycdn_confidence() {
        let parser = BunnyCDNLogParser;

        let bunnycdn_line = "HIT|200|1758146509371|164848|4029805|172.56.107.128|-|https://example.com/path|WA|curl/7.74.0|8af30092aac1a36890efd0c82857cb1b|US";
        assert!(parser.confidence(bunnycdn_line) > 0.8);

        let apache_line =
            "192.168.1.1 - - [01/Jan/2025:12:00:00 +0000] \"GET /index.html HTTP/1.1\" 200 1234";
        assert!(parser.confidence(apache_line) < 0.3);
    }
}
