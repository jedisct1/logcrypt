use super::formats::LogFormat;
use super::patterns::{APACHE_LOG_PATTERN, CLF_LOG_PATTERN};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct FormatDetectionResult {
    pub format: LogFormat,
    #[allow(dead_code)]
    pub confidence: f32,
}

pub fn detect_format(lines: &[String]) -> FormatDetectionResult {
    let mut scores: HashMap<LogFormat, f32> = HashMap::new();

    let sample_size = lines.len().min(50);
    let sample = &lines[0..sample_size];

    for line in sample {
        if line.trim().is_empty() {
            continue;
        }

        if APACHE_LOG_PATTERN.is_match(line) {
            *scores.entry(LogFormat::ApacheCombined).or_insert(0.0) += 1.0;
        }

        if CLF_LOG_PATTERN.is_match(line) {
            *scores.entry(LogFormat::CommonLog).or_insert(0.0) += 1.0;
        }

        if line.trim().starts_with('{')
            && line.trim().ends_with('}')
            && serde_json::from_str::<Value>(line).is_ok()
        {
            *scores.entry(LogFormat::Json).or_insert(0.0) += 1.0;
        }

        if contains_syslog_pattern(line) {
            *scores.entry(LogFormat::Syslog).or_insert(0.0) += 1.0;
        }

        if line.contains(" ERROR ")
            || line.contains(" WARN ")
            || line.contains(" INFO ")
            || line.contains(" DEBUG ")
        {
            *scores.entry(LogFormat::ApplicationLog).or_insert(0.0) += 0.5;
        }
    }

    let total_lines = sample.iter().filter(|l| !l.trim().is_empty()).count() as f32;

    let mut best_format = LogFormat::Unknown;
    let mut best_score = 0.0;

    for (format, score) in scores.iter() {
        let normalized_score = score / total_lines;
        if normalized_score > best_score {
            best_score = normalized_score;
            best_format = format.clone();
        }
    }

    if best_score < 0.3 {
        best_format = LogFormat::Unknown;
    }

    FormatDetectionResult {
        format: best_format,
        confidence: best_score,
    }
}

fn contains_syslog_pattern(line: &str) -> bool {
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    for month in &months {
        if line.contains(month)
            && line.contains(':')
            && line.chars().filter(|&c| c == ':').count() >= 3
        {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apache_format_detection() {
        let lines = vec![
            "192.168.1.1 - - [16/Sep/2025:03:00:09 +0000] \"GET /index.html HTTP/1.1\" 200 1234 \"-\" \"Mozilla/5.0\"".to_string(),
            "10.0.0.1 - - [16/Sep/2025:03:00:10 +0000] \"POST /api/login HTTP/1.1\" 301 567 \"http://example.com\" \"Chrome/91.0\"".to_string(),
        ];

        let result = detect_format(&lines);
        assert!(matches!(result.format, LogFormat::ApacheCombined));
        assert!(result.confidence > 0.8);
    }

    #[test]
    fn test_json_format_detection() {
        let lines = vec![
            r#"{"timestamp":"2025-09-16T03:00:09Z","ip":"192.168.1.1","method":"GET","path":"/index.html","status":200}"#.to_string(),
            r#"{"timestamp":"2025-09-16T03:00:10Z","ip":"10.0.0.1","method":"POST","path":"/api/login","status":301}"#.to_string(),
        ];

        let result = detect_format(&lines);
        assert!(matches!(result.format, LogFormat::Json));
        assert!(result.confidence > 0.8);
    }
}
