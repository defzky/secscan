use std::path::Path;

use crate::report::{Category, Finding, Severity};
use super::Scanner;

pub struct NginxScanner;

impl Scanner for NginxScanner {
    fn name(&self) -> &'static str {
        "Nginx Auditor"
    }

    fn scan(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check if nginx is installed
        let nginx_paths = vec![
            "/etc/nginx/nginx.conf",
            "/usr/local/nginx/conf/nginx.conf",
        ];

        let mut config_path = None;
        for p in &nginx_paths {
            if Path::new(p).exists() {
                config_path = Some(p.to_string());
                break;
            }
        }

        match config_path {
            Some(path) => {
                findings.push(Finding {
                    category: Category::Nginx,
                    severity: Severity::Info,
                    title: format!("Nginx config found at {}", path),
                    description: "Nginx configuration is present.".to_string(),
                    remediation: "Review configuration for security headers and TLS settings.".to_string(),
                    raw: Some(serde_json::json!({"config_path": path})),
                });

                // Read main config
                let config = std::fs::read_to_string(&path).unwrap_or_default();

                // Check for common security misconfigurations
                let checks: Vec<(&str, &str, Severity, &str, &str)> = vec![
                    ("server_tokens off", "server_tokens", Severity::High,
                     "Nginx version info is exposed in HTTP responses.",
                     "Add: server_tokens off; in http block"),
                    ("proxy_hide_header", "", Severity::Medium,
                     "Missing proxy_hide_header for internal headers.",
                     "Consider hiding upstream headers: proxy_hide_header X-Powered-By;"),
                    ("add_header X-Frame-Options", "X-Frame-Options", Severity::High,
                     "Missing X-Frame-Options. Site can be embedded in iframes (clickjacking).",
                     "Add: add_header X-Frame-Options SAMEORIGIN always;"),
                    ("add_header X-Content-Type-Options", "X-Content-Type-Options", Severity::High,
                     "Missing X-Content-Type-Options header (MIME sniffing protection).",
                     "Add: add_header X-Content-Type-Options nosniff always;"),
                    ("add_header X-XSS-Protection", "X-XSS-Protection", Severity::Medium,
                     "Missing XSS protection header.",
                     "Add: add_header X-XSS-Protection '1; mode=block' always;"),
                    ("add_header Strict-Transport-Security", "HSTS", Severity::Medium,
                     "Missing HSTS header. HTTPS downgrade attacks possible.",
                     "Add: add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;"),
                    ("ssl_protocols", "SSL Protocols", Severity::Critical,
                     "Check if old/insecure TLS versions are enabled.",
                     "Use only TLSv1.2 and TLSv1.3: ssl_protocols TLSv1.2 TLSv1.3;"),
                    ("ssl_ciphers", "SSL Ciphers", Severity::High,
                     "Weak or outdated SSL ciphers may be in use.",
                     "Use modern cipher suite: ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;"),
                ];

                for (search, label, sev, desc, fix) in &checks {
                    let found = if label.is_empty() {
                        config.contains(search)
                    } else {
                        config.contains(search)
                    };

                    if !found {
                        findings.push(Finding {
                            category: Category::Nginx,
                            severity: sev.clone(),
                            title: format!("Nginx: {} not configured", label),
                            description: desc.to_string(),
                            remediation: fix.to_string(),
                            raw: None,
                        });
                    } else {
                        findings.push(Finding {
                            category: Category::Nginx,
                            severity: Severity::Info,
                            title: format!("Nginx: {} is configured ✓", label),
                            description: "Security header is present.".to_string(),
                            remediation: "None needed.".to_string(),
                            raw: None,
                        });
                    }
                }

                // Check for listening on all interfaces
                if config.contains("listen 80") || config.contains("listen 443") {
                    // Check if bound to specific IP
                    if !config.contains("listen 127.0.0.1:80") && !config.contains("listen 127.0.0.1:443") {
                        findings.push(Finding {
                            category: Category::Nginx,
                            severity: Severity::Low,
                            title: "Nginx listens on all interfaces (0.0.0.0)".to_string(),
                            description: "Nginx binds to all network interfaces. If proxying internal services, bind them to localhost.".to_string(),
                            remediation: "Use listen 127.0.0.1:PORT for internal services, or ensure firewall restricts access.".to_string(),
                            raw: None,
                        });
                    }
                }
            }
            None => {
                findings.push(Finding {
                    category: Category::Nginx,
                    severity: Severity::Info,
                    title: "Nginx not installed".to_string(),
                    description: "Nginx configuration not found on this system.".to_string(),
                    remediation: "N/A".to_string(),
                    raw: None,
                });
            }
        }

        findings
    }
}
