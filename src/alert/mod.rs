/// Alert management — deduplication, LLM enrichment, and persistence.
use std::collections::HashSet;
use std::sync::Mutex;

use chrono::Utc;
use uuid::Uuid;

use crate::models::{
    Alert, AlertContext, AlertRepository, FlowSnapshot, RawAlert, Result,
    SummaryProvider,
};

pub struct AlertManager {
    summarizer: Box<dyn SummaryProvider>,
    repo: Box<dyn AlertRepository>,
    seen: Mutex<HashSet<(Uuid, String)>>,
}

impl AlertManager {
    pub fn new(
        summarizer: Box<dyn SummaryProvider>,
        repo: Box<dyn AlertRepository>,
    ) -> Self {
        Self {
            summarizer,
            repo,
            seen: Mutex::new(HashSet::new()),
        }
    }

    pub async fn dispatch(
        &self,
        raw: RawAlert,
        snap: FlowSnapshot,
        ) -> Result<Option<Alert>> {
        let dedup_key = (raw.flow_id, raw.title.clone());

        {
            let mut seen = self.seen.lock().unwrap();
            if !seen.insert(dedup_key) {
                return Ok(None);
            }
        }

        let ctx = AlertContext {
            alert: raw.clone(),
            flow_snapshot: snap,
        };

        let summary = self.summarizer.summarize(&ctx).await?;

        let alert = Alert {
            alert_id: Uuid::new_v4(),
            flow_id: raw.flow_id,
            created_at: Utc::now(),
            kind: raw.kind,
            severity: raw.severity,
            title: raw.title,
            detail: raw.detail,
            llm_summary: Some(summary),
        };

        self.repo.save(&alert).await?;

        Ok(Some(alert))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        AlertFilter, AlertKind, BoxFuture, Flow, FlowSnapshot, Protocol,
        Severity,
    };
    use chrono::{TimeZone, Utc};
    use std::net::IpAddr;
    use std::sync::{Arc, Mutex as StdMutex};

    // -- Shared mock state --

    #[derive(Default)]
    struct MockState {
        summarize_calls: u32,
        saved_alerts: Vec<Alert>,
    }

    // -- Mock SummaryProvider --

    struct MockSummarizer {
        response: String,
        state: Arc<StdMutex<MockState>>,
    }

    impl MockSummarizer {
        fn new(response: &str, state: Arc<StdMutex<MockState>>) -> Self {
            Self {
                response: response.to_string(),
                state,
            }
        }
    }

    impl SummaryProvider for MockSummarizer {
        fn summarize<'a>(&'a self, _ctx: &'a AlertContext) -> BoxFuture<'a, Result<String>> {
            Box::pin(async move {
                self.state.lock().unwrap().summarize_calls += 1;
                Ok(self.response.clone())
            })
        }
    }

    // -- Mock AlertRepository --

    struct MockRepo {
        state: Arc<StdMutex<MockState>>,
    }

    impl MockRepo {
        fn new(state: Arc<StdMutex<MockState>>) -> Self {
            Self { state }
        }
    }

    impl AlertRepository for MockRepo {
        fn save<'a>(&'a self, alert: &'a Alert) -> BoxFuture<'a, Result<Uuid>> {
            Box::pin(async move {
                self.state.lock().unwrap().saved_alerts.push(alert.clone());
                Ok(alert.alert_id)
            })
        }

        fn find_by_id<'a>(&'a self, _id: Uuid) -> BoxFuture<'a, Result<Option<Alert>>> {
            Box::pin(async { Ok(None) })
        }

        fn query<'a>(&'a self, _filter: &'a AlertFilter) -> BoxFuture<'a, Result<Vec<Alert>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    // -- Helpers --

    fn make_raw_alert(flow_id: Uuid, title: &str) -> RawAlert {
        RawAlert {
            flow_id,
            kind: AlertKind::SignatureMatch,
            severity: Severity::High,
            title: title.into(),
            detail: "test detail".into(),
        }
    }

    fn make_snapshot(flow_id: Uuid) -> FlowSnapshot {
        FlowSnapshot {
            flow: Flow {
                flow_id,
                src_ip: IpAddr::from([10, 0, 0, 1]),
                dst_ip: IpAddr::from([10, 0, 0, 2]),
                src_port: 12345,
                dst_port: 80,
                protocol: Protocol::Tcp,
                started_at: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
                last_seen_at: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 10).unwrap(),
                packet_count: 100,
                byte_count: 5000,
                avg_packet_len: 50.0,
                avg_inter_arrival_ms: 100.0,
                syn_count: 1,
                fin_count: 0,
            },
            captured_at: Utc::now(),
        }
    }

    // -- Tests --

    fn make_manager(state: Arc<StdMutex<MockState>>) -> AlertManager {
        AlertManager::new(
            Box::new(MockSummarizer::new("This is a mock summary.", state.clone())),
            Box::new(MockRepo::new(state)),
        )
    }

    #[tokio::test]
    async fn dispatch_enriches_and_persists() {
        let state = Arc::new(StdMutex::new(MockState::default()));
        let manager = make_manager(state.clone());

        let flow_id = Uuid::new_v4();
        let raw = make_raw_alert(flow_id, "Port Scan");
        let snap = make_snapshot(flow_id);

        let result = manager.dispatch(raw, snap).await.unwrap();
        assert!(result.is_some());

        let alert = result.unwrap();
        assert_eq!(alert.flow_id, flow_id);
        assert_eq!(alert.kind, AlertKind::SignatureMatch);
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.title, "Port Scan");
        assert_eq!(alert.llm_summary, Some("This is a mock summary.".into()));

        let s = state.lock().unwrap();
        assert_eq!(s.summarize_calls, 1);
        assert_eq!(s.saved_alerts.len(), 1);
    }

    #[tokio::test]
    async fn dispatch_deduplicates_same_flow_and_title() {
        let state = Arc::new(StdMutex::new(MockState::default()));
        let manager = make_manager(state.clone());

        let flow_id = Uuid::new_v4();
        let snap = make_snapshot(flow_id);

        let first = manager
            .dispatch(make_raw_alert(flow_id, "Port Scan"), snap.clone())
            .await
            .unwrap();
        assert!(first.is_some());

        let second = manager
            .dispatch(make_raw_alert(flow_id, "Port Scan"), snap.clone())
            .await
            .unwrap();
        assert!(second.is_none(), "duplicate should be suppressed");

        let s = state.lock().unwrap();
        assert_eq!(s.summarize_calls, 1, "summarizer should only be called once");
        assert_eq!(s.saved_alerts.len(), 1);
    }

    #[tokio::test]
    async fn dispatch_allows_different_titles_same_flow() {
        let state = Arc::new(StdMutex::new(MockState::default()));
        let manager = make_manager(state.clone());

        let flow_id = Uuid::new_v4();
        let snap = make_snapshot(flow_id);

        let first = manager
            .dispatch(make_raw_alert(flow_id, "Port Scan"), snap.clone())
            .await
            .unwrap();
        assert!(first.is_some());

        let second = manager
            .dispatch(make_raw_alert(flow_id, "SYN Flood"), snap.clone())
            .await
            .unwrap();
        assert!(second.is_some(), "different title should not be deduped");
    }

    #[tokio::test]
    async fn dispatch_allows_same_title_different_flow() {
        let state = Arc::new(StdMutex::new(MockState::default()));
        let manager = make_manager(state.clone());

        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();

        let first = manager
            .dispatch(make_raw_alert(id_a, "Port Scan"), make_snapshot(id_a))
            .await
            .unwrap();
        assert!(first.is_some());

        let second = manager
            .dispatch(make_raw_alert(id_b, "Port Scan"), make_snapshot(id_b))
            .await
            .unwrap();
        assert!(second.is_some(), "same title on different flow should not be deduped");
    }
}
