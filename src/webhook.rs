use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::report::{ScanReport, Finding, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    pub min_severity: String,     // "critical", "high", "medium", "all"
    pub format: String,           // "json", "telegram", "openclaw"
}

impl Default for WebhookConfig {
    fn default() -> Self {
        WebhookConfig {
            url: String::new(),
            min_severity: "high".to_string(),
            format: "json".to_string(),
        }
    }
}

/// Send scan findings via webhook
pub fn send_webhook(report: &ScanReport, config: &WebhookConfig) -> Result<(), String> {
    if config.url.is_empty() {
        return Ok(());
    }

    let min_sev = match config.min_severity.as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "all" => 3,
        _ => 1,
    };

    let filtered: Vec<&Finding> = report.findings.iter()
        .filter(|f| severity_level(&f.severity) >= min_sev)
        .collect();

    if filtered.is_empty() {
        eprintln!("  No findings above '{}' threshold. Skipping webhook.", config.min_severity);
        return Ok(());
    }

    match config.format.as_str() {
        "telegram" => send_telegram(report, &filtered, &config.url)?,
        "openclaw" => send_openclaw(report, &filtered, &config.url)?,
        _ => send_json(report, &filtered, &config.url)?,
    }

    Ok(())
}

fn severity_level(sev: &Severity) -> u8 {
    match sev {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

fn send_json(_report: &ScanReport, findings: &[&Finding], url: &str) -> Result<(), String> {
    let payload = serde_json::json!({
        "source": "secscan",
        "count": findings.len(),
        "findings": findings,
    });

    post_json(url, &payload)
}

fn send_telegram(report: &ScanReport, findings: &[&Finding], url: &str) -> Result<(), String> {
    let emoji = |s: &Severity| -> &str {
        match s {
            Severity::Critical => "🚨",
            Severity::High => "🔴",
            Severity::Medium => "🟡",
            Severity::Low => "🟢",
            Severity::Info => "ℹ️",
        }
    };

    let mut msg = format!(
        "🛡️ <b>secscan — {} | {} findings</b>\n\n",
        report.hostname, report.total_findings
    );

    // Group by severity
    let mut groups: HashMap<String, Vec<&&Finding>> = HashMap::new();
    for f in findings {
        groups.entry(f.severity.to_string()).or_default().push(f);
    }

    for (sev, items) in &[("CRITICAL", "High"), ("HIGH", "Medium"), ("MEDIUM", "Low")] {
        if let Some(grp) = groups.get(*sev) {
            for f in grp {
                msg.push_str(&format!(
                    "{} <b>[{}]</b> {}\n",
                    emoji(&f.severity), f.category, f.title
                ));
                msg.push_str(&format!("  <code>{}</code>\n", f.description.chars().take(120).collect::<String>()));
                msg.push_str(&format!("  → {}\n\n", f.remediation.chars().take(100).collect::<String>()));
            }
        }
    }

    // Telegram Bot API format
    let payload = serde_json::json!({
        "text": msg,
        "parse_mode": "HTML",
        "disable_web_page_preview": true,
    });

    post_json(url, &payload)
}

fn send_openclaw(report: &ScanReport, findings: &[&Finding], url: &str) -> Result<(), String> {
    let summary: Vec<serde_json::Value> = findings.iter().map(|f| {
        serde_json::json!({
            "severity": f.severity.to_string(),
            "category": f.category.to_string(),
            "title": f.title,
        })
    }).collect();

    let payload = serde_json::json!({
        "event": "secscan.alert",
        "hostname": report.hostname,
        "timestamp": report.timestamp,
        "summary": format!("{} findings ({} critical, {} high)",
            report.total_findings, report.criticals, report.highs),
        "findings": summary,
    });

    post_json(url, &payload)
}

fn post_json(url: &str, payload: &serde_json::Value) -> Result<(), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("HTTP client: {}", e))?;

    let resp = client
        .post(url)
        .json(payload)
        .send()
        .map_err(|e| format!("Request failed: {}", e))?;

    let status = resp.status();
    if status.is_success() || status.is_redirection() {
        eprintln!("  ✓ Webhook sent (HTTP {})", status);
        Ok(())
    } else {
        let body = resp.text().unwrap_or_default();
        Err(format!("Webhook returned {}: {}", status, body.chars().take(200).collect::<String>()))
    }
}
