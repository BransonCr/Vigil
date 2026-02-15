/// REST API layer — serves alerts and flows over HTTP via axum.
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use uuid::Uuid;

use crate::models::{
    AlertFilter, AlertKind, AlertRepository, FlowRepository, Result,
    Severity, VigilError,
};

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub alerts: Arc<dyn AlertRepository>,
    pub flows: Arc<dyn FlowRepository>,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/alerts", get(list_alerts))
        .route("/api/alerts/:id", get(get_alert))
        .route("/api/flows", get(list_flows))
        .route("/api/flows/:id", get(get_flow))
        .with_state(state)
}

pub async fn serve(addr: SocketAddr, state: AppState) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| VigilError::Api(e.to_string()))?;

    tracing::info!("API listening on {addr}");

    axum::serve(listener, router(state))
        .await
        .map_err(|e| VigilError::Api(e.to_string()))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

#[derive(Deserialize, Default)]
struct AlertQuery {
    severity: Option<String>,
    kind: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

async fn list_alerts(
    Query(q): Query<AlertQuery>,
    State(state): State<AppState>,
) -> std::result::Result<impl IntoResponse, AppError> {
    let severity = q.severity.as_deref().map(parse_severity).transpose()?;
    let kind = q.kind.as_deref().map(parse_alert_kind).transpose()?;

    let filter = AlertFilter {
        severity,
        kind,
        limit: q.limit,
        offset: q.offset,
    };

    let alerts = state.alerts.query(&filter).await?;
    Ok(Json(alerts))
}

async fn get_alert(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> std::result::Result<impl IntoResponse, AppError> {
    let uuid = Uuid::parse_str(&id)
        .map_err(|_| AppError::BadRequest(format!("invalid UUID: {id}")))?;

    match state.alerts.find_by_id(uuid).await? {
        Some(alert) => Ok(Json(alert).into_response()),
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

#[derive(Deserialize, Default)]
struct FlowQuery {
    limit: Option<i64>,
    offset: Option<i64>,
}

async fn list_flows(
    Query(q): Query<FlowQuery>,
    State(state): State<AppState>,
) -> std::result::Result<impl IntoResponse, AppError> {
    let limit = q.limit.unwrap_or(100);
    let offset = q.offset.unwrap_or(0);

    let flows = state.flows.list(limit, offset).await?;
    Ok(Json(flows))
}

async fn get_flow(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> std::result::Result<impl IntoResponse, AppError> {
    let uuid = Uuid::parse_str(&id)
        .map_err(|_| AppError::BadRequest(format!("invalid UUID: {id}")))?;

    match state.flows.find_by_id(uuid).await? {
        Some(flow) => Ok(Json(flow).into_response()),
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum AppError {
    BadRequest(String),
    Internal(VigilError),
}

impl From<VigilError> for AppError {
    fn from(e: VigilError) -> Self {
        AppError::Internal(e)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        match self {
            AppError::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": msg }))).into_response()
            }
            AppError::Internal(e) => {
                tracing::error!("internal error: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "internal server error" })),
                )
                    .into_response()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Query param parsers
// ---------------------------------------------------------------------------

fn parse_severity(s: &str) -> std::result::Result<Severity, AppError> {
    match s.to_lowercase().as_str() {
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        other => Err(AppError::BadRequest(format!("unknown severity: {other}"))),
    }
}

fn parse_alert_kind(s: &str) -> std::result::Result<AlertKind, AppError> {
    match s.to_lowercase().as_str() {
        "signature_match" | "signature" => Ok(AlertKind::SignatureMatch),
        "anomaly_detected" | "anomaly" => Ok(AlertKind::AnomalyDetected),
        other => Err(AppError::BadRequest(format!("unknown alert kind: {other}"))),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        Alert, AlertKind, BoxFuture, Flow, Protocol, Result as VigilResult,
        Severity,
    };
    use axum::body::Body;
    use chrono::{TimeZone, Utc};
    use http_body_util::BodyExt;
    use std::net::IpAddr;
    use tower::ServiceExt;

    // -- Mock repos --

    struct MockAlertRepo {
        alerts: Vec<Alert>,
    }

    impl AlertRepository for MockAlertRepo {
        fn save<'a>(&'a self, alert: &'a Alert) -> BoxFuture<'a, VigilResult<Uuid>> {
            Box::pin(async { Ok(alert.alert_id) })
        }

        fn find_by_id<'a>(&'a self, id: Uuid) -> BoxFuture<'a, VigilResult<Option<Alert>>> {
            let found = self.alerts.iter().find(|a| a.alert_id == id).cloned();
            Box::pin(async move { Ok(found) })
        }

        fn query<'a>(&'a self, filter: &'a AlertFilter) -> BoxFuture<'a, VigilResult<Vec<Alert>>> {
            let mut results: Vec<Alert> = self.alerts.clone();

            if let Some(sev) = filter.severity {
                results.retain(|a| a.severity == sev);
            }
            if let Some(kind) = filter.kind {
                results.retain(|a| a.kind == kind);
            }

            let offset = filter.offset.unwrap_or(0) as usize;
            let limit = filter.limit.unwrap_or(100) as usize;
            let results: Vec<Alert> = results.into_iter().skip(offset).take(limit).collect();

            Box::pin(async move { Ok(results) })
        }
    }

    struct MockFlowRepo {
        flows: Vec<Flow>,
    }

    impl FlowRepository for MockFlowRepo {
        fn save<'a>(&'a self, _flow: &'a Flow) -> BoxFuture<'a, VigilResult<()>> {
            Box::pin(async { Ok(()) })
        }

        fn find_by_id<'a>(&'a self, id: Uuid) -> BoxFuture<'a, VigilResult<Option<Flow>>> {
            let found = self.flows.iter().find(|f| f.flow_id == id).cloned();
            Box::pin(async move { Ok(found) })
        }

        fn list<'a>(&'a self, limit: i64, offset: i64) -> BoxFuture<'a, VigilResult<Vec<Flow>>> {
            let results: Vec<Flow> = self
                .flows
                .iter()
                .skip(offset as usize)
                .take(limit as usize)
                .cloned()
                .collect();
            Box::pin(async move { Ok(results) })
        }
    }

    // -- Helpers --

    fn sample_alert(id: Uuid, severity: Severity, kind: AlertKind) -> Alert {
        Alert {
            alert_id: id,
            flow_id: Uuid::new_v4(),
            created_at: Utc.with_ymd_and_hms(2025, 6, 15, 14, 0, 0).unwrap(),
            kind,
            severity,
            title: "Test alert".into(),
            detail: "details".into(),
            llm_summary: Some("LLM says hi".into()),
        }
    }

    fn sample_flow(id: Uuid) -> Flow {
        Flow {
            flow_id: id,
            src_ip: IpAddr::from([10, 0, 0, 1]),
            dst_ip: IpAddr::from([10, 0, 0, 2]),
            src_port: 12345,
            dst_port: 80,
            protocol: Protocol::Tcp,
            started_at: Utc.with_ymd_and_hms(2025, 6, 15, 14, 0, 0).unwrap(),
            last_seen_at: Utc.with_ymd_and_hms(2025, 6, 15, 14, 0, 30).unwrap(),
            packet_count: 100,
            byte_count: 5000,
            avg_packet_len: 50.0,
            avg_inter_arrival_ms: 100.0,
            syn_count: 1,
            fin_count: 1,
        }
    }

    fn test_state(alerts: Vec<Alert>, flows: Vec<Flow>) -> AppState {
        AppState {
            alerts: Arc::new(MockAlertRepo { alerts }),
            flows: Arc::new(MockFlowRepo { flows }),
        }
    }

    async fn body_to_string(body: Body) -> String {
        let bytes = body.collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    // -- Health --

    #[tokio::test]
    async fn health_returns_ok() {
        let app = router(test_state(vec![], vec![]));

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        assert!(body.contains("\"status\":\"ok\""));
    }

    // -- Alerts --

    #[tokio::test]
    async fn list_alerts_returns_all() {
        let alerts = vec![
            sample_alert(Uuid::new_v4(), Severity::High, AlertKind::SignatureMatch),
            sample_alert(Uuid::new_v4(), Severity::Low, AlertKind::AnomalyDetected),
        ];
        let app = router(test_state(alerts, vec![]));

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/alerts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[tokio::test]
    async fn list_alerts_filters_by_severity() {
        let alerts = vec![
            sample_alert(Uuid::new_v4(), Severity::High, AlertKind::SignatureMatch),
            sample_alert(Uuid::new_v4(), Severity::Low, AlertKind::SignatureMatch),
            sample_alert(Uuid::new_v4(), Severity::High, AlertKind::AnomalyDetected),
        ];
        let app = router(test_state(alerts, vec![]));

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/alerts?severity=high")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[tokio::test]
    async fn list_alerts_filters_by_kind() {
        let alerts = vec![
            sample_alert(Uuid::new_v4(), Severity::High, AlertKind::SignatureMatch),
            sample_alert(Uuid::new_v4(), Severity::High, AlertKind::AnomalyDetected),
        ];
        let app = router(test_state(alerts, vec![]));

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/alerts?kind=anomaly")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.len(), 1);
    }

    #[tokio::test]
    async fn get_alert_returns_found() {
        let id = Uuid::new_v4();
        let alerts = vec![sample_alert(id, Severity::High, AlertKind::SignatureMatch)];
        let app = router(test_state(alerts, vec![]));

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri(&format!("/api/alerts/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        assert!(body.contains(&id.to_string()));
    }

    #[tokio::test]
    async fn get_alert_returns_404() {
        let app = router(test_state(vec![], vec![]));

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri(&format!("/api/alerts/{}", Uuid::new_v4()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_alert_rejects_bad_uuid() {
        let app = router(test_state(vec![], vec![]));

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/alerts/not-a-uuid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // -- Flows --

    #[tokio::test]
    async fn list_flows_returns_all() {
        let flows = vec![sample_flow(Uuid::new_v4()), sample_flow(Uuid::new_v4())];
        let app = router(test_state(vec![], flows));

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/flows")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[tokio::test]
    async fn list_flows_respects_pagination() {
        let flows = vec![
            sample_flow(Uuid::new_v4()),
            sample_flow(Uuid::new_v4()),
            sample_flow(Uuid::new_v4()),
        ];
        let app = router(test_state(vec![], flows));

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/flows?limit=2&offset=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[tokio::test]
    async fn get_flow_returns_found() {
        let id = Uuid::new_v4();
        let flows = vec![sample_flow(id)];
        let app = router(test_state(vec![], flows));

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri(&format!("/api/flows/{id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_string(resp.into_body()).await;
        assert!(body.contains(&id.to_string()));
    }

    #[tokio::test]
    async fn get_flow_returns_404() {
        let app = router(test_state(vec![], vec![]));

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri(&format!("/api/flows/{}", Uuid::new_v4()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -- Query param parsing --

    #[test]
    fn parse_severity_valid() {
        assert_eq!(parse_severity("low").unwrap(), Severity::Low);
        assert_eq!(parse_severity("HIGH").unwrap(), Severity::High);
        assert_eq!(parse_severity("Critical").unwrap(), Severity::Critical);
    }

    #[test]
    fn parse_severity_invalid() {
        assert!(parse_severity("extreme").is_err());
    }

    #[test]
    fn parse_alert_kind_valid() {
        assert_eq!(parse_alert_kind("signature").unwrap(), AlertKind::SignatureMatch);
        assert_eq!(parse_alert_kind("signature_match").unwrap(), AlertKind::SignatureMatch);
        assert_eq!(parse_alert_kind("anomaly").unwrap(), AlertKind::AnomalyDetected);
        assert_eq!(parse_alert_kind("ANOMALY_DETECTED").unwrap(), AlertKind::AnomalyDetected);
    }

    #[test]
    fn parse_alert_kind_invalid() {
        assert!(parse_alert_kind("unknown").is_err());
    }
}
