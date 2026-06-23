use std::process::Command;
use std::time::Instant;

use clap::Parser;
use colored::*;

mod api;
mod report;
mod scanner;
mod webhook;

use report::{ScanReport, Severity};
use scanner::Scanner;

#[derive(Parser)]
#[command(name = "secscan", about = "AI Ops Security Scanner")]
struct Cli {
    /// Output format: json, html, terminal
    #[arg(short, long, default_value = "terminal")]
    format: String,

    /// Only run specific modules: port, service, system, docker, nginx, ssh
    #[arg(short, long)]
    modules: Option<Vec<String>>,

    /// Output file path
    #[arg(short, long)]
    output: Option<String>,

    /// Start HTTP API server on specified port (default: 9090)
    #[arg(long)]
    serve: Option<Option<u16>>,

    /// Webhook URL for sending scan reports (used with --serve)
    #[arg(long)]
    webhook: Option<String>,
}

pub fn get_hostname() -> String {
    Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

/// Run scan with optional module filter. Returns findings.
pub fn run_scan_modules(module_filter: &Option<Vec<String>>) -> Vec<report::Finding> {
    let mut all_findings = Vec::new();

    let scanners: Vec<Box<dyn Scanner>> = vec![
        Box::new(scanner::port::PortScanner),
        Box::new(scanner::service::ServiceScanner),
        Box::new(scanner::system::SystemScanner),
        Box::new(scanner::docker::DockerScanner),
        Box::new(scanner::nginx::NginxScanner),
        Box::new(scanner::ssh::SshScanner),
    ];

    for scanner in scanners {
        let name = scanner.name();
        let allowed = module_filter.as_ref().map_or(true, |filter| {
            let key = name.to_lowercase().split_whitespace().next().unwrap_or("").to_string();
            filter.iter().any(|f| key.contains(f))
        });

        if !allowed {
            continue;
        }

        eprintln!("{}", format!("\n── {} ──", name).cyan().bold());
        let findings = scanner.scan();
        for f in &findings {
            eprintln!("  [{}] {}", f.severity, f.title);
        }
        all_findings.extend(findings);
    }

    all_findings
}

fn run_scan(cli: &Cli) -> ScanReport {
    let start = Instant::now();
    let module_filter = cli.modules.as_ref().map(|m| {
        m.iter().map(|s| s.to_lowercase()).collect::<Vec<_>>()
    });

    let all_findings = run_scan_modules(&module_filter);
    ScanReport::new(get_hostname(), start.elapsed().as_millis() as u64, all_findings)
}

fn print_terminal(report: &ScanReport) {
    println!("\n{}", "═".repeat(60));
    println!("{}", "🛡️  AI Ops Security Scanner Report".bold());
    println!("{}", "═".repeat(60));
    println!("{}: {}", "Hostname".bold(), report.hostname);
    println!("{}: {}", "Timestamp".bold(), report.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("{}: {}ms", "Duration".bold(), report.duration_ms);
    println!();

    let summary = format!(
        "CRITICAL: {}  HIGH: {}  MEDIUM: {}  LOW: {}  INFO: {}",
        report.criticals.to_string().red().bold(),
        report.highs.to_string().yellow().bold(),
        report.mediums.to_string().yellow(),
        report.lows.to_string().normal(),
        report.infos.to_string().dimmed(),
    );
    println!("{}", summary);
    println!();

    for (i, finding) in report.findings.iter().enumerate() {
        let sev_color = match finding.severity {
            Severity::Critical => "CRITICAL".red().bold(),
            Severity::High => "HIGH".yellow().bold(),
            Severity::Medium => "MEDIUM".yellow(),
            Severity::Low => "LOW".normal(),
            Severity::Info => "INFO".dimmed(),
        };

        println!("{}. [{}] [{}] {}", 
            i + 1,
            sev_color,
            format!("{}", finding.category).blue(),
            finding.title.bold(),
        );
        println!("   {}", finding.description);
        println!("   {} {}", "→".green(), finding.remediation);
        println!();
    }
}

fn save_report(report: &ScanReport, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(report)?;
    std::fs::write(path, json)?;
    eprintln!("{} Report saved to {}", "✓".green(), path);
    Ok(())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    // API server mode
    if let Some(port_opt) = cli.serve {
        let port = port_opt.unwrap_or(9090);
        return api::start_api(port, cli.webhook.clone()).await;
    }

    // CLI mode
    let uid = unsafe { libc::geteuid() };
    if uid != 0 {
        eprintln!("{}", "⚠️  Warning: Not running as root. Some checks will be limited.".yellow());
        eprintln!("{}", "   Run with sudo for full scan coverage.\n".yellow());
    }

    let report = run_scan(&cli);

    // Save report if output path specified
    if let Some(path) = &cli.output {
        if let Err(e) = save_report(&report, path) {
            eprintln!("{} Failed to save report: {}", "✗".red(), e);
        }
    }

    match cli.format.as_str() {
        "json" => println!("{}", serde_json::to_string_pretty(&report).unwrap()),
        "terminal" => print_terminal(&report),
        _ => print_terminal(&report),
    }

    if report.criticals > 0 || report.highs > 0 {
        std::process::exit(1);
    }

    Ok(())
}
