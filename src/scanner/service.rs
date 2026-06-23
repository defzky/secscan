use std::process::Command;

use crate::report::{Category, Finding, Severity};
use super::Scanner;

pub struct ServiceScanner;

impl Scanner for ServiceScanner {
    fn name(&self) -> &'static str {
        "Service Auditor"
    }

    fn scan(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check running services via systemctl
        let output = Command::new("systemctl")
            .args(["list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"])
            .output();

        let services = match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                stdout.lines()
                    .filter_map(|l| l.split_whitespace().next())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            }
            _ => {
                findings.push(Finding {
                    category: Category::Service,
                    severity: Severity::Low,
                    title: "Cannot enumerate systemd services".to_string(),
                    description: "Failed to run systemctl. May be running in container or without systemd.".to_string(),
                    remediation: "Ensure systemd is available, or run with sufficient permissions.".to_string(),
                    raw: None,
                });
                return findings;
            }
        };

        findings.push(Finding {
            category: Category::Service,
            severity: Severity::Info,
            title: format!("{} running services", services.len()),
            description: format!("Services: {}", services.join(", ")),
            remediation: "Review service list. Remove unused services, disable unnecessary ones.".to_string(),
            raw: Some(serde_json::json!({ "services": services })),
        });

        // Check for services running as root
        let ps = Command::new("ps")
            .args(["aux", "--no-headers"])
            .output();

        if let Ok(out) = ps {
            if out.status.success() {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let root_services: Vec<&str> = stdout.lines()
                    .filter(|l| l.starts_with("root") && !l.contains("[") && !l.contains("kworker"))
                    .filter_map(|l| l.split_whitespace().nth(10))
                    .collect();

                if root_services.len() > 20 {
                    findings.push(Finding {
                        category: Category::Service,
                        severity: Severity::Low,
                        title: format!("{} processes running as root", root_services.len()),
                        description: format!("Root processes: {}", root_services[..20.min(root_services.len())].join(", ")),
                        remediation: "Follow principle of least privilege. Run services as dedicated users with minimum permissions.".to_string(),
                        raw: None,
                    });
                }
            }
        }

        findings
    }
}
