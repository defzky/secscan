use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use actix_cors::Cors;
use actix_web::{web, App, HttpServer, HttpResponse};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::report::ScanReport;
use crate::webhook;

/// In-memory report store (thread-safe)
pub struct ReportStore {
    reports: HashMap<String, ScanReport>,
    latest_id: Option<String>,
}

impl ReportStore {
    pub fn new() -> Self {
        ReportStore {
            reports: HashMap::new(),
            latest_id: None,
        }
    }

    pub fn store(&mut self, id: String, report: ScanReport) {
        self.latest_id = Some(id.clone());
        self.reports.insert(id, report);
    }

    pub fn get(&self, id: &str) -> Option<&ScanReport> {
        self.reports.get(id)
    }

    pub fn latest(&self) -> Option<&ScanReport> {
        self.latest_id.as_ref().and_then(|id| self.reports.get(id))
    }

    pub fn list_ids(&self) -> Vec<String> {
        self.reports.keys().cloned().collect()
    }
}

#[derive(Deserialize)]
pub struct ScanQuery {
    pub modules: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct WebhookConfig {
    pub url: String,
    pub min_severity: String,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        WebhookConfig {
            url: String::new(),
            min_severity: "high".to_string(),
        }
    }
}

#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

fn ok_response<T: Serialize>(data: T) -> HttpResponse {
    HttpResponse::Ok().json(ApiResponse {
        success: true,
        data: Some(data),
        error: None,
    })
}

fn error_response(msg: &str) -> HttpResponse {
    HttpResponse::InternalServerError().json(ApiResponse::<()> {
        success: false,
        data: None,
        error: Some(msg.to_string()),
    })
}

async fn trigger_scan(
    query: web::Query<ScanQuery>,
    store: web::Data<Mutex<ReportStore>>,
    webhook_cfg: web::Data<Mutex<WebhookConfig>>,
) -> HttpResponse {
    let modules: Option<Vec<String>> = query.modules.as_ref().map(|m| {
        m.split(',').map(|s| s.trim().to_lowercase()).collect()
    });

    let start = Instant::now();

    let hostname = crate::get_hostname();
    let findings = crate::run_scan_modules(&modules);

    let duration_ms = start.elapsed().as_millis() as u64;
    let report = ScanReport::new(hostname, duration_ms, findings);
    let report_id = Uuid::new_v4().to_string();

    if let Ok(mut store) = store.lock() {
        store.store(report_id.clone(), report.clone());
    }

    // Send webhook if configured (non-blocking)
    if let Ok(cfg) = webhook_cfg.lock() {
        if !cfg.url.is_empty() {
            let wh = webhook::WebhookConfig {
                url: cfg.url.clone(),
                min_severity: cfg.min_severity.clone(),
                format: "json".to_string(),
            };
            let _ = webhook::send_webhook(&report, &wh);
        }
    }

    ok_response(serde_json::json!({
        "report_id": report_id,
        "summary": {
            "duration_ms": report.duration_ms,
            "total": report.total_findings,
            "criticals": report.criticals,
            "highs": report.highs,
            "mediums": report.mediums,
            "lows": report.lows,
        },
        "findings": report.findings,
    }))
}

async fn trigger_quick_scan(
    store: web::Data<Mutex<ReportStore>>,
    webhook_cfg: web::Data<Mutex<WebhookConfig>>,
) -> HttpResponse {
    let start = Instant::now();
    let hostname = crate::get_hostname();
    let modules = Some(vec!["port".to_string(), "service".to_string()]);
    let findings = crate::run_scan_modules(&modules);
    let duration_ms = start.elapsed().as_millis() as u64;
    let report = ScanReport::new(hostname, duration_ms, findings);
    let report_id = Uuid::new_v4().to_string();

    if let Ok(mut store) = store.lock() {
        store.store(report_id.clone(), report.clone());
    }

    if let Ok(cfg) = webhook_cfg.lock() {
        if !cfg.url.is_empty() {
            let wh = webhook::WebhookConfig {
                url: cfg.url.clone(),
                min_severity: cfg.min_severity.clone(),
                format: "json".to_string(),
            };
            let _ = webhook::send_webhook(&report, &wh);
        }
    }

    ok_response(serde_json::json!({
        "report_id": report_id,
        "summary": {
            "duration_ms": report.duration_ms,
            "total": report.total_findings,
            "criticals": report.criticals,
            "highs": report.highs,
        },
        "findings": report.findings,
    }))
}

async fn get_latest_report(
    store: web::Data<Mutex<ReportStore>>,
) -> HttpResponse {
    match store.lock() {
        Ok(store) => match store.latest() {
            Some(report) => ok_response(report.clone()),
            None => error_response("No reports yet. Run a scan first."),
        },
        Err(_) => error_response("Store lock failed"),
    }
}

async fn get_report(
    path: web::Path<String>,
    store: web::Data<Mutex<ReportStore>>,
) -> HttpResponse {
    let id = path.into_inner();
    match store.lock() {
        Ok(store) => match store.get(&id) {
            Some(report) => ok_response(report.clone()),
            None => error_response(&format!("Report '{}' not found", id)),
        },
        Err(_) => error_response("Store lock failed"),
    }
}

async fn list_reports(
    store: web::Data<Mutex<ReportStore>>,
) -> HttpResponse {
    match store.lock() {
        Ok(store) => ok_response(store.list_ids()),
        Err(_) => error_response("Store lock failed"),
    }
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "service": "secscan",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// POST /webhook/config — set webhook URL
/// POST /webhook/test — send test ping
async fn set_webhook(
    body: web::Json<WebhookConfig>,
    cfg: web::Data<Mutex<WebhookConfig>>,
) -> HttpResponse {
    let new_cfg = body.into_inner();
    if let Ok(mut c) = cfg.lock() {
        c.url = new_cfg.url;
        c.min_severity = new_cfg.min_severity;
    }
    ok_response(serde_json::json!({"status": "webhook configured"}))
}

async fn webhook_status(
    cfg: web::Data<Mutex<WebhookConfig>>,
) -> HttpResponse {
    let status = match cfg.lock() {
        Ok(c) => serde_json::json!({
            "configured": !c.url.is_empty(),
            "url": c.url,
            "min_severity": c.min_severity,
        }),
        Err(_) => serde_json::json!({"configured": false}),
    };
    ok_response(status)
}

pub async fn start_api(port: u16, webhook_url: Option<String>) -> std::io::Result<()> {
    let store = web::Data::new(Mutex::new(ReportStore::new()));
    let webhook_cfg = web::Data::new(Mutex::new(WebhookConfig {
        url: webhook_url.unwrap_or_default(),
        min_severity: "high".to_string(),
    }));

    eprintln!("🛡️  secscan API server starting on http://127.0.0.1:{}", port);

    // Log webhook status
    {
        let cfg = webhook_cfg.lock().unwrap();
        if !cfg.url.is_empty() {
            eprintln!("  Webhook configured: {}", cfg.url);
        } else {
            eprintln!("  No webhook configured. Set via POST /webhook/config");
        }
    }

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(cors)
            .app_data(store.clone())
            .app_data(webhook_cfg.clone())
            .route("/health", web::get().to(health))
            .route("/scan", web::post().to(trigger_scan))
            .route("/scan/quick", web::post().to(trigger_quick_scan))
            .route("/report/latest", web::get().to(get_latest_report))
            .route("/report/{id}", web::get().to(get_report))
            .route("/reports", web::get().to(list_reports))
            .route("/webhook/config", web::post().to(set_webhook))
            .route("/webhook/status", web::get().to(webhook_status))
    })
    .bind(format!("127.0.0.1:{}", port))?
    .run()
    .await
}
