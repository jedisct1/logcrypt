use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    pub static ref IPV4_PATTERN: Regex = Regex::new(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ).unwrap();

    pub static ref IPV6_PATTERN: Regex = Regex::new(
        r"(?i)\b(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:(?:(?::[0-9a-f]{1,4}){1,6})|:(?:(?::[0-9a-f]{1,4}){1,7}|:)|fe80:(?::[0-9a-f]{0,4}){0,4}%[0-9a-z]+|::(?:ffff(?::0{1,4})?:)?(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])|(?:[0-9a-f]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1?[0-9])?[0-9]))\b"
    ).unwrap();

    pub static ref URI_PATTERN: Regex = Regex::new(
        r#"(?i)\b(?:(?:https?|ftp|ftps|ssh|git|svn|ws|wss)://)?(?:[a-z0-9\-._~%!$&'()*+,;=:]+@)?(?:[a-z0-9\-._~%]+|\[[0-9a-f:]+\])(?::[0-9]+)?(?:/[a-z0-9\-._~%!$&'()*+,;=:@/]*)?(?:\?[a-z0-9\-._~%!$&'()*+,;=:@/?]*)?(?:#[a-z0-9\-._~%!$&'()*+,;=:@/?]*)?"#
    ).unwrap();

    pub static ref HTTP_PATH_PATTERN: Regex = Regex::new(
        r#"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(/[^\s?]*(?:\?[^\s]*)?)"#
    ).unwrap();

    pub static ref URL_IN_QUOTES_PATTERN: Regex = Regex::new(
        r#"["'](\w+://[^"'\s]+)["']"#
    ).unwrap();

    pub static ref APACHE_LOG_PATTERN: Regex = Regex::new(
        r#"^([^\s]+)\s+[^\s]+\s+[^\s]+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+|-)\s+"([^"]*)"\s+"([^"]*)"#
    ).unwrap();

    pub static ref CLF_LOG_PATTERN: Regex = Regex::new(
        r#"^([^\s]+)\s+[^\s]+\s+[^\s]+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+|-)"#
    ).unwrap();
}

#[derive(Debug, Clone)]
pub struct IpMatch {
    pub start: usize,
    pub end: usize,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct UriMatch {
    pub start: usize,
    pub end: usize,
    pub value: String,
}

pub fn find_all_ips(text: &str) -> Vec<IpMatch> {
    let mut matches = Vec::new();

    for mat in IPV4_PATTERN.find_iter(text) {
        matches.push(IpMatch {
            start: mat.start(),
            end: mat.end(),
            value: mat.as_str().to_string(),
        });
    }

    for mat in IPV6_PATTERN.find_iter(text) {
        matches.push(IpMatch {
            start: mat.start(),
            end: mat.end(),
            value: mat.as_str().to_string(),
        });
    }

    matches.sort_by_key(|m| m.start);
    matches
}

pub fn find_all_uris(text: &str) -> Vec<UriMatch> {
    let mut matches = Vec::new();
    let mut seen_ranges = Vec::new();

    for mat in URL_IN_QUOTES_PATTERN.captures_iter(text) {
        if let Some(url_match) = mat.get(1) {
            let range = (url_match.start(), url_match.end());
            if !overlaps_with_seen(&seen_ranges, range) {
                matches.push(UriMatch {
                    start: url_match.start(),
                    end: url_match.end(),
                    value: url_match.as_str().to_string(),
                });
                seen_ranges.push(range);
            }
        }
    }

    for mat in HTTP_PATH_PATTERN.captures_iter(text) {
        if let Some(path_match) = mat.get(1) {
            let range = (path_match.start(), path_match.end());
            if !overlaps_with_seen(&seen_ranges, range) {
                matches.push(UriMatch {
                    start: path_match.start(),
                    end: path_match.end(),
                    value: path_match.as_str().to_string(),
                });
                seen_ranges.push(range);
            }
        }
    }

    for mat in URI_PATTERN.find_iter(text) {
        let url_str = mat.as_str();
        if url_str.contains("://") || url_str.starts_with("www.") {
            let range = (mat.start(), mat.end());
            if !overlaps_with_seen(&seen_ranges, range) {
                matches.push(UriMatch {
                    start: mat.start(),
                    end: mat.end(),
                    value: url_str.to_string(),
                });
                seen_ranges.push(range);
            }
        }
    }

    matches.sort_by_key(|m| m.start);
    matches
}

fn overlaps_with_seen(seen_ranges: &[(usize, usize)], range: (usize, usize)) -> bool {
    for &(start, end) in seen_ranges {
        if (range.0 >= start && range.0 < end)
            || (range.1 > start && range.1 <= end)
            || (range.0 <= start && range.1 >= end)
        {
            return true;
        }
    }
    false
}
