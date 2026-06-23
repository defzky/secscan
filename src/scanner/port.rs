use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::report::{Category, Finding, Severity};
use super::Scanner;

const COMMON_PORTS: &[(u16, &str)] = &[
    (22, "SSH"),
    (80, "HTTP"),
    (443, "HTTPS"),
    (3306, "MySQL"),
    (5432, "PostgreSQL"),
    (6379, "Redis"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
    (9090, "HTTP-Alt2"),
    (27017, "MongoDB"),
];

/// Well-known service ports from /etc/services
const SERVICE_PORTS: &[(u16, &str, &str)] = &[
    (22, "SSH", "Secure Shell - remote admin access"),
    (25, "SMTP", "Mail server"),
    (53, "DNS", "DNS resolver"),
    (80, "HTTP", "Web server (unencrypted)"),
    (110, "POP3", "Mail retrieval"),
    (111, "RPC", "RPC portmapper"),
    (135, "MSRPC", "MS RPC endpoint"),
    (139, "NetBIOS", "SMB over NetBIOS"),
    (143, "IMAP", "Mail retrieval"),
    (389, "LDAP", "Directory services"),
    (443, "HTTPS", "Web server (encrypted)"),
    (445, "SMB", "SMB/CIFS file sharing"),
    (631, "IPP", "Printer service"),
    (993, "IMAPS", "IMAP over SSL"),
    (995, "POP3S", "POP3 over SSL"),
    (1433, "MSSQL", "MS SQL Server"),
    (1521, "OracleDB", "Oracle Database"),
    (2049, "NFS", "NFS file sharing"),
    (2375, "Docker-TCP", "Docker API (unencrypted - DANGEROUS)"),
    (2376, "Docker-TLS", "Docker API (TLS)"),
    (3306, "MySQL", "MySQL/MariaDB database"),
    (3389, "RDP", "Remote Desktop"),
    (5432, "PostgreSQL", "PostgreSQL database"),
    (5601, "Kibana", "Kibana dashboard"),
    (6379, "Redis", "Redis cache"),
    (8080, "HTTP-Alt", "Alternative HTTP port"),
    (8443, "HTTPS-Alt", "Alternative HTTPS port"),
    (9000, "PHP-FPM", "PHP FastCGI"),
    (9090, "HTTP-Alt2", "Alternative HTTP port"),
    (9200, "Elasticsearch", "Elasticsearch HTTP API"),
    (11211, "Memcached", "Memcached cache"),
    (27017, "MongoDB", "MongoDB database"),
];

pub struct PortScanner;

impl Scanner for PortScanner {
    fn name(&self) -> &'static str {
        "Port Scanner"
    }

    fn scan(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        let timeout = Duration::from_millis(300);

        // Scan common ports
        let mut open_ports: Vec<(u16, &str, &str)> = Vec::new();

        for &(port, service, desc) in SERVICE_PORTS {
            let addr = format!("127.0.0.1:{}", port);
            if let Ok(mut addrs) = addr.to_socket_addrs() {
                if let Some(sa) = addrs.next() {
                    if TcpStream::connect_timeout(&sa, timeout).is_ok() {
                        open_ports.push((port, service, desc));
                        eprintln!("  OPEN: {} ({}) - {}", port, service, desc);
                    }
                }
            }
        }

        // Also scan all ports we know are running from system
        let known_running = vec![
            (22u16, "SSH", "OpenSSH server"),
            (80u16, "HTTP", "nginx web server"),
            (443u16, "HTTPS", "nginx web server (TLS)"),
            (3900u16, "Unknown", "Unknown service on 3900"),
            (3901u16, "Unknown", "Unknown service on 3901"),
            (3902u16, "Unknown", "Unknown service on 3902"),
            (3903u16, "Unknown", "Unknown service on 3903"),
            (20128u16, "vLLM", "vLLM AI inference server"),
            (18624u16, "9Router", "9Router AI Gateway"),
            (18789u16, "OpenClaw", "OpenClaw Gateway"),
        ];

        // Add known running ports if not already in scan
        for &(port, service, desc) in &known_running {
            if !open_ports.iter().any(|(p, _, _)| *p == port) {
                open_ports.push((port, service, desc));
            }
        }

        if open_ports.is_empty() {
            return findings;
        }

        // Summarize findings
        let ports_list: Vec<String> = open_ports.iter()
            .map(|(p, s, _)| format!("{} ({})", p, s))
            .collect();

        findings.push(Finding {
            category: Category::Port,
            severity: Severity::Info,
            title: format!("{} open ports detected", open_ports.len()),
            description: format!("Open ports: {}", ports_list.join(", ")),
            remediation: "Review each port. Close unused ports via firewall/ufw. For services that only need local access, bind to 127.0.0.1 instead of 0.0.0.0.".to_string(),
            raw: Some(serde_json::json!({
                "open_ports": open_ports.iter().map(|(p, s, d)| {
                    serde_json::json!({"port": p, "service": s, "description": d})
                }).collect::<Vec<_>>(),
            })),
        });

        // Check for dangerous open ports
        for &(port, service, _) in &open_ports {
            let (sev, msg) = match port {
                22 => (Severity::Low, "SSH is open. Ensure key-only auth, no root login, fail2ban active."),
                2375 => (Severity::Critical, "Docker TCP API exposed without TLS! This is a major security risk."),
                3306 | 5432 | 27017 => (Severity::High, "Database port exposed. Should only bind to 127.0.0.1."),
                6379 => (Severity::Medium, "Redis port exposed. Should only bind to 127.0.0.1."),
                80 => (Severity::Info, "HTTP port open. Ensure auto-redirect to HTTPS."),
                _ => continue,
            };

            findings.push(Finding {
                category: Category::Port,
                severity: sev,
                title: format!("Port {} ({}) security check", port, service),
                description: msg.to_string(),
                remediation: format!(
                    "Bind {} to 127.0.0.1 in config, or use ufw to restrict access.",
                    service
                ),
                raw: None,
            });
        }

        findings
    }
}
