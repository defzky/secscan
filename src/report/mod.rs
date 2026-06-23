use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Category {
    Port,
    Service,
    Docker,
    Nginx,
    Ssh,
    System,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Category::Port => write!(f, "PORT"),
            Category::Service => write!(f, "SERVICE"),
            Category::Docker => write!(f, "DOCKER"),
            Category::Nginx => write!(f, "NGINX"),
            Category::Ssh => write!(f, "SSH"),
            Category::System => write!(f, "SYSTEM"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub remediation: String,
    pub raw: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub timestamp: DateTime<Utc>,
    pub hostname: String,
    pub duration_ms: u64,
    pub total_findings: u32,
    pub criticals: u32,
    pub highs: u32,
    pub mediums: u32,
    pub lows: u32,
    pub infos: u32,
    pub findings: Vec<Finding>,
}

impl ScanReport {
    pub fn new(hostname: String, duration_ms: u64, findings: Vec<Finding>) -> Self {
        let total = findings.len() as u32;
        let criticals = findings.iter().filter(|f| matches!(f.severity, Severity::Critical)).count() as u32;
        let highs = findings.iter().filter(|f| matches!(f.severity, Severity::High)).count() as u32;
        let mediums = findings.iter().filter(|f| matches!(f.severity, Severity::Medium)).count() as u32;
        let lows = findings.iter().filter(|f| matches!(f.severity, Severity::Low)).count() as u32;
        let infos = findings.iter().filter(|f| matches!(f.severity, Severity::Info)).count() as u32;

        ScanReport {
            timestamp: Utc::now(),
            hostname,
            duration_ms,
            total_findings: total,
            criticals,
            highs,
            mediums,
            lows,
            infos,
            findings,
        }
    }
}
