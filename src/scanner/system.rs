use std::process::Command;

use crate::report::{Category, Finding, Severity};
use super::Scanner;

pub struct SystemScanner;

impl Scanner for SystemScanner {
    fn name(&self) -> &'static str {
        "System Auditor"
    }

    fn scan(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // UFW status
        let ufw = Command::new("ufw")
            .arg("status")
            .output();

        match ufw {
            Ok(out) => {
                let status = String::from_utf8_lossy(&out.stdout);
                if status.contains("inactive") || status.is_empty() {
                    findings.push(Finding {
                        category: Category::System,
                        severity: Severity::High,
                        title: "Firewall is inactive".to_string(),
                        description: "UFW firewall is not enabled. Server has open ports with no firewall rules.".to_string(),
                        remediation: "Enable UFW: sudo ufw default deny incoming, sudo ufw default allow outgoing, sudo ufw allow ssh, sudo ufw enable".to_string(),
                        raw: Some(serde_json::json!({"ufw_status": status.trim()})),
                    });
                } else {
                    findings.push(Finding {
                        category: Category::System,
                        severity: Severity::Info,
                        title: "Firewall is active".to_string(),
                        description: format!("UFW status:\n{}", status),
                        remediation: "Review firewall rules periodically.".to_string(),
                        raw: None,
                    });
                }
            }
            Err(_) => {
                findings.push(Finding {
                    category: Category::System,
                    severity: Severity::Info,
                    title: "UFW not installed".to_string(),
                    description: "UFW firewall not found on system.".to_string(),
                    remediation: "Consider installing UFW: sudo apt install ufw".to_string(),
                    raw: None,
                });
            }
        }

        // Check disk usage
        let df = Command::new("df")
            .args(["-h", "/"])
            .output();

        if let Ok(out) = df {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let lines: Vec<&str> = stdout.lines().collect();
            if lines.len() > 1 {
                let parts: Vec<&str> = lines[1].split_whitespace().collect();
                if parts.len() >= 5 {
                    let usage_str = parts[4].trim_end_matches('%');
                    if let Ok(usage) = usage_str.parse::<u8>() {
                        let (sev, msg) = match usage {
                            0..=50 => (Severity::Info, "Disk usage is healthy."),
                            51..=80 => (Severity::Low, "Disk usage is moderate."),
                            81..=90 => (Severity::Medium, "Disk usage is concerning."),
                            91..=95 => (Severity::High, "Disk is nearly full!"),
                            _ => (Severity::Critical, "Disk is critically full!"),
                        };
                        findings.push(Finding {
                            category: Category::System,
                            severity: sev,
                            title: format!("Root disk usage: {}%", usage),
                            description: msg.to_string(),
                            remediation: "Clean up old logs, Docker images, or unused packages. Consider expanding disk.".to_string(),
                            raw: Some(serde_json::json!({"disk_usage_percent": usage})),
                        });
                    }
                }
            }
        }

        // Check memory
        let mem = Command::new("free")
            .arg("-m")
            .output();

        if let Ok(out) = mem {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let lines: Vec<&str> = stdout.lines().collect();
            if lines.len() > 1 {
                let parts: Vec<&str> = lines[1].split_whitespace().collect();
                if parts.len() >= 3 {
                    let total = parts[1].parse::<f64>().unwrap_or(0.0);
                    let avail = parts[6].parse::<f64>().unwrap_or(0.0);
                    let pct = if total > 0.0 { ((total - avail) / total * 100.0) as u8 } else { 0 };

                    let (sev, msg) = match pct {
                        0..=50 => (Severity::Info, "Memory usage is healthy."),
                        51..=75 => (Severity::Low, "Memory usage is elevated."),
                        76..=90 => (Severity::Medium, "Memory usage is high."),
                        _ => (Severity::High, "Memory is critically low!"),
                    };

                    findings.push(Finding {
                        category: Category::System,
                        severity: sev,
                        title: format!("Memory usage: {}% ({:.0}MB / {:.0}MB)", pct, total - avail, total),
                        description: msg.to_string(),
                        remediation: "Close unused services. Consider adding swap or upgrading RAM.".to_string(),
                        raw: Some(serde_json::json!({
                            "memory_total_mb": total,
                            "memory_available_mb": avail,
                            "memory_used_pct": pct,
                        })),
                    });
                }
            }
        }

        // Kernel parameters - check if IP forwarding is on
        let ip_fwd = Command::new("sysctl")
            .args(["-n", "net.ipv4.ip_forward"])
            .output();

        if let Ok(out) = ip_fwd {
            let val = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if val == "1" {
                findings.push(Finding {
                    category: Category::System,
                    severity: Severity::Medium,
                    title: "IP forwarding is enabled".to_string(),
                    description: "net.ipv4.ip_forward = 1. This allows the server to act as a router.".to_string(),
                    remediation: "Disable if not needed: sudo sysctl -w net.ipv4.ip_forward=0".to_string(),
                    raw: None,
                });
            }
        }

        findings
    }
}
