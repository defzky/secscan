use std::path::Path;

use crate::report::{Category, Finding, Severity};
use super::Scanner;

pub struct SshScanner;

impl Scanner for SshScanner {
    fn name(&self) -> &'static str {
        "SSH Auditor"
    }

    fn scan(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Find SSH config
        let paths = vec![
            "/etc/ssh/sshd_config",
            "/etc/ssh/sshd_config.d/",
        ];

        let mut config_content = String::new();
        let mut config_found = false;

        for path in &paths {
            if Path::new(path).exists() {
                config_found = true;
                if path.ends_with(".d/") {
                    // Include files in config.d
                    if let Ok(entries) = std::fs::read_dir(path) {
                        for entry in entries.flatten() {
                            if entry.path().extension().map_or(false, |e| e == "conf") {
                                if let Ok(c) = std::fs::read_to_string(entry.path()) {
                                    config_content.push_str(&c);
                                    config_content.push('\n');
                                }
                            }
                        }
                    }
                } else {
                    if let Ok(c) = std::fs::read_to_string(path) {
                        config_content.push_str(&c);
                    }
                }
            }
        }

        if !config_found {
            findings.push(Finding {
                category: Category::Ssh,
                severity: Severity::High,
                title: "SSH config not found".to_string(),
                description: "Cannot locate sshd_config. SSH may not be installed or config is in unexpected location.".to_string(),
                remediation: "Ensure OpenSSH server is installed: sudo apt install openssh-server".to_string(),
                raw: None,
            });
            return findings;
        }

        let checks: Vec<(&str, Severity, &str, &str)> = vec![
            ("PermitRootLogin", Severity::Critical, "Root login via SSH is enabled (or not explicitly denied)",
             "Set: PermitRootLogin no"),
            ("PasswordAuthentication", Severity::Critical, "Password authentication for SSH is enabled — brute force risk",
             "Set: PasswordAuthentication no\nThen restart SSH and use only SSH keys."),
            ("PubkeyAuthentication", Severity::High, "Public key authentication should be explicitly enabled",
             "Set: PubkeyAuthentication yes"),
            ("Port", Severity::Low, "SSH running on default port 22 — automated attacks target this",
             "Consider changing to a non-standard port: Port 2222\nEnsure firewall allows the new port."),
            ("AllowUsers", Severity::Medium, "No AllowUsers restriction — any valid user can SSH",
             "Restrict to specific users: AllowUsers youruser"),
            ("MaxAuthTries", Severity::Medium, "No MaxAuthTries set — unlimited auth attempts per connection",
             "Set: MaxAuthTries 3"),
            ("ClientAliveInterval", Severity::Low, "No idle timeout set — stale SSH sessions accumulate",
             "Set: ClientAliveInterval 300\nSet: ClientAliveCountMax 2"),
            ("UsePAM", Severity::Medium, "PAM is enabled for SSH — configuration depends on PAM modules",
             "Ensure PAM is configured correctly. Consider disabling if not needed."),
            ("X11Forwarding", Severity::Medium, "X11 forwarding may be enabled — potential security risk",
             "Set: X11Forwarding no"),
        ];

        for (directive, sev, desc, fix) in &checks {
            let found_value = find_value(&config_content, directive);
            let is_dangerous = match directive {
                &"PermitRootLogin" => {
                    found_value.as_deref().unwrap_or("prohibit-password") != "no"
                }
                &"PasswordAuthentication" => {
                    found_value.as_deref().unwrap_or("yes") != "no"
                }
                &"PubkeyAuthentication" => {
                    found_value.as_deref().unwrap_or("yes") != "yes"
                }
                &"Port" => found_value.is_some(),
                &"AllowUsers" => found_value.is_none(),
                &"MaxAuthTries" => found_value.is_none(),
                &"ClientAliveInterval" => found_value.is_none(),
                &"UsePAM" => {
                    found_value.as_deref().unwrap_or("yes") == "yes"
                }
                &"X11Forwarding" => {
                    found_value.as_deref().unwrap_or("no") != "no"
                }
                _ => false,
            };

            if is_dangerous {
                findings.push(Finding {
                    category: Category::Ssh,
                    severity: sev.clone(),
                    title: format!("SSH: {} is misconfigured", directive),
                    description: desc.to_string(),
                    remediation: fix.to_string(),
                    raw: Some(serde_json::json!({
                        "directive": directive,
                        "current": found_value.unwrap_or_default(),
                    })),
                });
            } else if let Some(val) = found_value {
                findings.push(Finding {
                    category: Category::Ssh,
                    severity: Severity::Info,
                    title: format!("SSH: {} = {}", directive, val),
                    description: format!("SSH directive '{}' is set to recommended value.", directive),
                    remediation: "No action needed.".to_string(),
                    raw: None,
                });
            }
        }

        // Check SSH keys
        // Read authorized_keys files to check their permissions
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        let auth_keys_path = format!("{}/.ssh/authorized_keys", home);

        if Path::new(&auth_keys_path).exists() {
            if let Ok(metadata) = std::fs::metadata(&auth_keys_path) {
                if metadata.permissions().readonly() {
                    // Check if it's too permissive
                    // We can't fully check permissions cross-platform, so just note it
                }
            }

            let key_count = std::fs::read_to_string(&auth_keys_path)
                .map(|s| s.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()).count())
                .unwrap_or(0);

            findings.push(Finding {
                category: Category::Ssh,
                severity: Severity::Info,
                title: format!("{} SSH keys configured (authorized_keys)", key_count),
                description: format!("Authorized keys file at: {}", auth_keys_path),
                remediation: "Review authorized keys regularly. Remove unused keys.".to_string(),
                raw: Some(serde_json::json!({"key_count": key_count})),
            });
        }

        findings
    }
}

fn find_value(config: &str, directive: &str) -> Option<String> {
    for line in config.lines() {
        let line = line.trim();
        // Skip comments
        if line.starts_with('#') {
            continue;
        }
        if line.to_lowercase().starts_with(directive.to_lowercase().as_str()) {
            let value = line.splitn(2, char::is_whitespace)
                .nth(1)
                .map(|s| s.trim().to_string());
            if let Some(v) = value {
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
    }
    None
}
