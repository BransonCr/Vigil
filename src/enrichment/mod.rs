/// LLM-powered alert enrichment via the Anthropic Messages API.
///
/// `LlmEnrichmentService` formats alert context into a structured prompt,
/// sends it to Claude, and returns a plain-English incident summary.
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::models::{
    AlertContext, AlertKind, BoxFuture, Result, SummaryProvider, VigilError,
};

const ANTHROPIC_API_URL: &str = "https://api.anthropic.com/v1/messages";
const DEFAULT_MODEL: &str = "claude-sonnet-4-5-20250929";
const MAX_TOKENS: u32 = 1024;

pub struct LlmEnrichmentService {
    http: Client,
    api_key: String,
    model: String,
}

impl LlmEnrichmentService {
    pub fn new(api_key: String) -> Self {
        Self {
            http: Client::new(),
            api_key,
            model: DEFAULT_MODEL.to_string(),
        }
    }

    pub fn with_model(api_key: String, model: String) -> Self {
        Self {
            http: Client::new(),
            api_key,
            model,
        }
    }

    pub fn build_prompt(ctx: &AlertContext) -> String {
        let flow = &ctx.flow_snapshot.flow;
        let alert = &ctx.alert;

        let kind_str = match alert.kind {
            AlertKind::SignatureMatch => "Signature Match",
            AlertKind::AnomalyDetected => "Anomaly Detected",
        };

        format!(
            "You are a network security analyst. Analyze this intrusion detection alert \
             and provide a concise incident summary.\n\n\
             ## Alert\n\
             - Type: {kind}\n\
             - Severity: {severity:?}\n\
             - Title: {title}\n\
             - Detail: {detail}\n\n\
             ## Flow Context\n\
             - Source: {src_ip}:{src_port}\n\
             - Destination: {dst_ip}:{dst_port}\n\
             - Protocol: {proto:?}\n\
             - Duration: {started} → {last_seen}\n\
             - Packets: {pkts}, Bytes: {bytes}\n\
             - Avg packet size: {avg_pkt:.1} bytes\n\
             - Avg inter-arrival: {avg_iat:.1} ms\n\
             - SYN count: {syn}, FIN count: {fin}\n\n\
             Respond with:\n\
             1. What happened (1-2 sentences)\n\
             2. Why it's suspicious (1-2 sentences)\n\
             3. Recommended action (1-2 sentences)",
            kind = kind_str,
            severity = alert.severity,
            title = alert.title,
            detail = alert.detail,
            src_ip = flow.src_ip,
            src_port = flow.src_port,
            dst_ip = flow.dst_ip,
            dst_port = flow.dst_port,
            proto = flow.protocol,
            started = flow.started_at.format("%H:%M:%S"),
            last_seen = flow.last_seen_at.format("%H:%M:%S"),
            pkts = flow.packet_count,
            bytes = flow.byte_count,
            avg_pkt = flow.avg_packet_len,
            avg_iat = flow.avg_inter_arrival_ms,
            syn = flow.syn_count,
            fin = flow.fin_count,
        )
    }
}

// ---------------------------------------------------------------------------
// Anthropic Messages API request/response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct MessagesRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<Message>,
}

#[derive(Serialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct MessagesResponse {
    content: Vec<ContentBlock>,
}

#[derive(Deserialize)]
struct ContentBlock {
    text: Option<String>,
}

impl SummaryProvider for LlmEnrichmentService {
    fn summarize<'a>(&'a self, ctx: &'a AlertContext) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            let prompt = Self::build_prompt(ctx);

            let body = MessagesRequest {
                model: self.model.clone(),
                max_tokens: MAX_TOKENS,
                messages: vec![Message {
                    role: "user".to_string(),
                    content: prompt,
                }],
            };

            let resp = self
                .http
                .post(ANTHROPIC_API_URL)
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| VigilError::Enrichment(e.to_string()))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(VigilError::Enrichment(format!(
                    "API returned {status}: {body}"
                )));
            }

            let parsed: MessagesResponse = resp
                .json()
                .await
                .map_err(|e| VigilError::Enrichment(e.to_string()))?;

            parsed
                .content
                .into_iter()
                .find_map(|block| block.text)
                .ok_or_else(|| {
                    VigilError::Enrichment("No text content in API response".to_string())
                })
        })
    }
}

// ---------------------------------------------------------------------------
// NoopSummarizer
// ---------------------------------------------------------------------------

pub struct NoopSummarizer;

impl SummaryProvider for NoopSummarizer {
    fn summarize<'a>(&'a self, ctx: &'a AlertContext) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            Ok(format!(
                "[{:?}] {:?} alert: {} — {}",
                ctx.alert.severity, ctx.alert.kind, ctx.alert.title, ctx.alert.detail
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AlertKind, Flow, FlowSnapshot, Protocol, RawAlert, Severity,
    };
    use chrono::{TimeZone, Utc};
    use std::net::IpAddr;
    use uuid::Uuid;

    fn sample_context() -> AlertContext {
        let flow = Flow {
            flow_id: Uuid::nil(),
            src_ip: IpAddr::from([10, 0, 0, 1]),
            dst_ip: IpAddr::from([10, 0, 0, 2]),
            src_port: 54321,
            dst_port: 22,
            protocol: Protocol::Tcp,
            started_at: Utc.with_ymd_and_hms(2025, 6, 15, 14, 30, 0).unwrap(),
            last_seen_at: Utc.with_ymd_and_hms(2025, 6, 15, 14, 30, 10).unwrap(),
            packet_count: 50,
            byte_count: 2000,
            avg_packet_len: 40.0,
            avg_inter_arrival_ms: 200.0,
            syn_count: 50,
            fin_count: 0,
        };

        AlertContext {
            alert: RawAlert {
                flow_id: flow.flow_id,
                kind: AlertKind::SignatureMatch,
                severity: Severity::High,
                title: "SSH Brute Force".into(),
                detail: "50 connection attempts to port 22 in 10s".into(),
            },
            flow_snapshot: FlowSnapshot {
                flow,
                captured_at: Utc::now(),
            },
        }
    }

    #[test]
    fn prompt_contains_alert_fields() {
        let ctx = sample_context();
        let prompt = LlmEnrichmentService::build_prompt(&ctx);

        assert!(prompt.contains("Signature Match"));
        assert!(prompt.contains("SSH Brute Force"));
        assert!(prompt.contains("50 connection attempts"));
        assert!(prompt.contains("High"));
    }

    #[test]
    fn prompt_contains_flow_context() {
        let ctx = sample_context();
        let prompt = LlmEnrichmentService::build_prompt(&ctx);

        assert!(prompt.contains("10.0.0.1:54321"));
        assert!(prompt.contains("10.0.0.2:22"));
        assert!(prompt.contains("Tcp"));
        assert!(prompt.contains("Packets: 50"));
        assert!(prompt.contains("Bytes: 2000"));
    }

    #[test]
    fn prompt_contains_statistical_fields() {
        let ctx = sample_context();
        let prompt = LlmEnrichmentService::build_prompt(&ctx);

        assert!(prompt.contains("40.0 bytes"));
        assert!(prompt.contains("200.0 ms"));
        assert!(prompt.contains("SYN count: 50"));
        assert!(prompt.contains("FIN count: 0"));
    }

    #[test]
    fn prompt_contains_response_instructions() {
        let ctx = sample_context();
        let prompt = LlmEnrichmentService::build_prompt(&ctx);

        assert!(prompt.contains("What happened"));
        assert!(prompt.contains("Why it's suspicious"));
        assert!(prompt.contains("Recommended action"));
    }

    #[test]
    fn prompt_handles_anomaly_kind() {
        let mut ctx = sample_context();
        ctx.alert.kind = AlertKind::AnomalyDetected;
        let prompt = LlmEnrichmentService::build_prompt(&ctx);

        assert!(prompt.contains("Anomaly Detected"));
        assert!(!prompt.contains("Signature Match"));
    }

    #[test]
    fn constructor_sets_default_model() {
        let svc = LlmEnrichmentService::new("test-key".into());
        assert_eq!(svc.model, DEFAULT_MODEL);
        assert_eq!(svc.api_key, "test-key");
    }

    #[test]
    fn with_model_overrides_default() {
        let svc = LlmEnrichmentService::with_model(
            "test-key".into(),
            "claude-opus-4-6".into(),
        );
        assert_eq!(svc.model, "claude-opus-4-6");
    }

    #[tokio::test]
    async fn summarize_returns_error_on_bad_url() {
        let short_client = Client::builder()
            .timeout(std::time::Duration::from_millis(1))
            .build()
            .unwrap();

        let svc = LlmEnrichmentService {
            http: short_client,
            api_key: "fake-key".into(),
            model: DEFAULT_MODEL.into(),
        };

        let ctx = sample_context();
        let result = svc.summarize(&ctx).await;

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("enrichment"),
            "error should be wrapped as Enrichment variant: {err}"
        );
    }
}
