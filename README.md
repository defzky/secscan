# 🛡️ secscan — AI Ops Security Scanner

Lightweight security scanner written in **Rust** for Linux servers. Scans ports, services, system config, Docker, Nginx & SSH — alerts via **Telegram** + **Web Dashboard**.

![Rust](https://img.shields.io/badge/lang-Rust-orange)
![Size](https://img.shields.io/badge/size-12MB-blue)
![API](https://img.shields.io/badge/API-Actix--web-green)

## Stack

| Layer | Tech | Port |
|-------|------|------|
| Scanner | Rust CLI | — |
| API Server | Actix-web | `:9090` |
| Dashboard | Python/HTML | `:9091` |
| Alert | Telegram Bot | — |
| Proxy | Nginx | `443` |

## Quick Start

```bash
# Run scan
secscan

# Run API server
secscan --serve 9090

# Scan + JSON output
secscan --format json --output report.json
```

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/scan` | Run full scan |
| `POST` | `/scan/quick` | Quick scan (port + service) |
| `GET` | `/report/latest` | Latest report |
| `GET` | `/report/{id}` | Report by ID |
| `GET` | `/reports` | List all reports |
| `GET` | `/health` | API health |
| `POST` | `/webhook/config` | Set webhook URL |
| `GET` | `/webhook/status` | Webhook status |

## Findings Status

| Severity | Count | Notes |
|----------|-------|-------|
| 🔴 Critical | 0 | All clear |
| 🟡 High | 2 | Firewall inactive, Docker userns remap |
| 🟢 Medium | 8 | Various config hardening |
| ⚪ Low | 4 | Non-critical issues |

## Architecture

```
                     ┌─────────────┐
                     │  Telegram   │
                     │  (alert)    │
                     └──────▲──────┘
                            │
┌──────┐  daily  ┌──────────┴──────────┐  proxy  ┌───────────┐
│ CLI  ├────────►│  API Server (:9090) │◄────────┤  Nginx    │
│ Rust │         │  + Report Store     │         │  :443     │
└──────┘         └──────────▲──────────┘         └───────────┘
                            │ proxy                     │
                     ┌──────┴──────┐            ┌───────┴────────┐
                     │  Dashboard  │◄───────────┤  openlabs.my.id│
                     │  (:9091)    │            │  /sec/         │
                     └─────────────┘            └────────────────┘
```

## Installation

```bash
# From source
cargo build --release
sudo cp target/release/secscan /usr/local/bin/

# Or download from releases
curl -LO https://github.com/defzky/secscan/releases/latest/download/secscan
chmod +x secscan && sudo mv secscan /usr/local/bin/
```

## Systemd Services

```bash
# API server (auto-start on boot)
sudo systemctl enable --now secscan.service

# Daily scan at 03:00 AM
sudo systemctl enable --now secscan-daily.timer

# Web dashboard
sudo systemctl enable --now secscan-dash.service
```

## Configuration

Set webhook via API:
```bash
curl -X POST http://127.0.0.1:9090/webhook/config \
  -H "Content-Type: application/json" \
  -d '{"url": "https://api.telegram.org/bot<TOKEN>/sendMessage", "min_severity": "high"}'
```

Or CLI flag:
```bash
secscan --serve 9090 --webhook "https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=..."
```

## Modules

- **Port Scanner** — TCP connect scan (common ports)
- **Service Scanner** — systemd service audit
- **System Scanner** — kernel parameters, firewall, memory
- **Docker Scanner** — daemon config, security defaults
- **Nginx Scanner** — TLS settings, security headers
- **SSH Scanner** — port, auth methods, hardening

## License

MIT
