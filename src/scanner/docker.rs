use std::process::Command;

use crate::report::{Category, Finding, Severity};
use super::Scanner;

pub struct DockerScanner;

impl Scanner for DockerScanner {
    fn name(&self) -> &'static str {
        "Docker Auditor"
    }

    fn scan(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check if Docker is available
        let version = Command::new("docker")
            .args(["version", "--format", "{{.Server.Version}}"])
            .output();

        match version {
            Ok(out) if out.status.success() => {
                let ver = String::from_utf8_lossy(&out.stdout).trim().to_string();
                findings.push(Finding {
                    category: Category::Docker,
                    severity: Severity::Info,
                    title: format!("Docker Engine v{} installed", ver),
                    description: "Docker is available and responding.".to_string(),
                    remediation: "Keep Docker updated to latest stable version.".to_string(),
                    raw: Some(serde_json::json!({"version": ver})),
                });
            }
            _ => {
                findings.push(Finding {
                    category: Category::Docker,
                    severity: Severity::Info,
                    title: "Docker not available".to_string(),
                    description: "Docker CLI not found or Docker daemon not running.".to_string(),
                    remediation: "Install Docker if needed: https://docs.docker.com/engine/install/".to_string(),
                    raw: None,
                });
                return findings;
            }
        }

        // List running containers
        let ps = Command::new("docker")
            .args(["ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"])
            .output();

        if let Ok(out) = ps {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let containers: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();

            if containers.is_empty() {
                findings.push(Finding {
                    category: Category::Docker,
                    severity: Severity::Info,
                    title: "No running containers".to_string(),
                    description: "No Docker containers are currently running.".to_string(),
                    remediation: "N/A".to_string(),
                    raw: None,
                });
            } else {
                findings.push(Finding {
                    category: Category::Docker,
                    severity: Severity::Info,
                    title: format!("{} running containers", containers.len()),
                    description: format!("Containers:\n{}", containers.join("\n")),
                    remediation: "Review each container. Remove unused ones, pin image versions.".to_string(),
                    raw: Some(serde_json::json!({
                        "containers": containers.iter().map(|c| {
                            let parts: Vec<&str> = c.split('\t').collect();
                            serde_json::json!({
                                "name": parts.get(0).unwrap_or(&"?"),
                                "image": parts.get(1).unwrap_or(&"?"),
                                "status": parts.get(2).unwrap_or(&"?"),
                                "ports": parts.get(3).unwrap_or(&""),
                            })
                        }).collect::<Vec<_>>(),
                    })),
                });
            }

            // Check for containers with published ports (exposed to host)
            for c in &containers {
                let parts: Vec<&str> = c.split('\t').collect();
                let name = parts.first().unwrap_or(&"?");
                let ports = parts.get(3).unwrap_or(&"");

                if ports.contains("0.0.0.0") {
                    findings.push(Finding {
                        category: Category::Docker,
                        severity: Severity::Medium,
                        title: format!("Container '{}' exposes ports to all interfaces", name),
                        description: format!("Ports: {}", ports),
                        remediation: "Bind containers to 127.0.0.1 if external access isn't needed. Use `-p 127.0.0.1:PORT:PORT` instead of `-p PORT:PORT`.".to_string(),
                        raw: None,
                    });
                }
            }
        }

        // Check for dangling images
        let dangling = Command::new("docker")
            .args(["images", "--filter", "dangling=true", "--format", "{{.Repository}}:{{.Tag}}"])
            .output();

        if let Ok(out) = dangling {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let dangles: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
            if !dangles.is_empty() {
                findings.push(Finding {
                    category: Category::Docker,
                    severity: Severity::Low,
                    title: format!("{} dangling images", dangles.len()),
                    description: "Unused dangling images waste disk space.".to_string(),
                    remediation: "Clean up: docker image prune".to_string(),
                    raw: Some(serde_json::json!({"dangling": dangles})),
                });
            }
        }

        // Check Docker daemon config for security
        let info = Command::new("docker")
            .args(["info", "--format", "{{json .}}"])
            .output();

        if let Ok(out) = info {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
                let checks = vec![
                    ("live_restore_enabled", "Live Restore", Severity::Medium, "Live restore is disabled. Containers won't survive daemon restart."),
                    ("userns_remap", "User Namespace Remap", Severity::High, "User namespace remapping is disabled. Containers run with root privileges mapping."),
                ];

                for (key, label, sev, desc) in checks {
                    let key_path: Vec<&str> = key.split('.').collect();
                    let val = key_path.iter().fold(&json, |acc, k| {
                        acc.get(k).unwrap_or(&serde_json::Value::Null)
                    });

                    if val.as_bool() == Some(false) || val.is_null() {
                        findings.push(Finding {
                            category: Category::Docker,
                            severity: sev,
                            title: format!("Docker: {} not configured", label),
                            description: desc.to_string(),
                            remediation: format!("Enable in /etc/docker/daemon.json: {{\"{}\": true}}", key),
                            raw: None,
                        });
                    }
                }
            }
        }

        findings
    }
}
