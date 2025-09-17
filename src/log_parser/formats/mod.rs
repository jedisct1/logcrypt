pub mod apache;
pub mod generic;
pub mod json;

use anyhow::Result;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LogFormat {
    ApacheCombined,
    CommonLog,
    Json,
    Syslog,
    ApplicationLog,
    Unknown,
}

impl LogFormat {
    pub fn name(&self) -> &str {
        match self {
            LogFormat::ApacheCombined => "Apache Combined",
            LogFormat::CommonLog => "Common Log Format",
            LogFormat::Json => "JSON",
            LogFormat::Syslog => "Syslog",
            LogFormat::ApplicationLog => "Application Log",
            LogFormat::Unknown => "Unknown",
        }
    }
}

pub trait LogLineParser {
    fn parse_line(&self, line: &str) -> Result<ParsedLogLine>;
}

#[derive(Debug, Clone)]
pub struct ParsedLogLine {
    pub original: String,
    pub ip_positions: Vec<(usize, usize, String)>,
    pub uri_positions: Vec<(usize, usize, String)>,
}
