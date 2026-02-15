/// End-to-end integration test: pcap replay → flow tracking → detection → alerting → API.
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use vigil::alert::AlertManager;
use vigil::api::{self, AppState};
use vigil::capture::{frame_builders::build_tcp_frame, PcapReplaySource};
use vigil::detection::{AnomalyDetector, DetectionEngine, SignatureEngine};
use vigil::enrichment::NoopSummarizer;
use vigil::flow::FlowTracker;
use vigil::models::{AlertRepository, FlowRepository, PacketSource};
use vigil::storage::SqliteStore;

async fn setup_store() -> Arc<SqliteStore> {
    let store = SqliteStore::connect("sqlite::memory:").await.unwrap();
    store.migrate().await.unwrap();
    Arc::new(store)
}

fn write_brute_force_pcap(path: &str) {
    let dead_cap = pcap::Capture::dead(pcap::Linktype::ETHERNET).unwrap();
    let mut savefile = dead_cap.savefile(path).unwrap();

    // 35 small TCP packets to port 22 on the same 5-tuple
    // Triggers BruteForce: tcp, dst_port in [22,23,3389], packet_count >= 30, avg_pkt < 100
    for i in 0..35u16 {
        let frame = build_tcp_frame(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            50000,
            22,   // SSH port
            0x02, // SYN flag
            b"",  // no payload → small packets
        );
        savefile.write(&pcap::Packet {
            header: &pcap::PacketHeader {
                ts: libc::timeval {
                    tv_sec: 1000 + i as i64,
                    tv_usec: 0,
                },
                caplen: frame.len() as u32,
                len: frame.len() as u32,
            },
            data: &frame,
        });
    }
    savefile.flush().unwrap();
}

#[tokio::test]
async fn full_pipeline_detects_brute_force() {
    let dir = tempfile::tempdir().unwrap();
    let pcap_path = dir.path().join("brute_force.pcap");
    write_brute_force_pcap(pcap_path.to_str().unwrap());

    let store = setup_store().await;

    let alert_manager = AlertManager::new(
        Box::new(NoopSummarizer),
        Box::new(Arc::clone(&store)),
    );

    let mut detection = DetectionEngine::new();
    detection.register(Box::new(SignatureEngine::with_defaults()));
    detection.register(Box::new(AnomalyDetector::new(3.0)));

    let mut flow_tracker = FlowTracker::new();
    let mut source = PcapReplaySource::open(pcap_path.to_str().unwrap()).unwrap();

    let mut alert_count = 0u32;
    while let Ok(Some(pkt)) = source.next_packet().await {
        let snap = flow_tracker.update(&pkt);

        FlowRepository::save(store.as_ref(), &snap.flow).await.unwrap();

        let alerts = detection.run(&snap).await.unwrap();
        for raw in alerts {
            if let Ok(Some(_alert)) = alert_manager.dispatch(raw, snap.clone()).await {
                alert_count += 1;
            }
        }
    }

    assert!(alert_count >= 1, "should have detected at least one alert");

    // Verify alerts were persisted
    let filter = vigil::models::AlertFilter {
        severity: None,
        kind: None,
        limit: Some(100),
        offset: Some(0),
    };
    let stored_alerts = AlertRepository::query(store.as_ref(), &filter)
        .await
        .unwrap();
    assert!(
        !stored_alerts.is_empty(),
        "alerts should be in the database"
    );
    assert_eq!(
        stored_alerts[0].kind,
        vigil::models::AlertKind::SignatureMatch
    );

    // Verify flows were persisted
    let flows = FlowRepository::list(store.as_ref(), 100, 0)
        .await
        .unwrap();
    assert!(!flows.is_empty(), "flows should be in the database");
}

#[tokio::test]
async fn api_serves_pipeline_results() {
    let dir = tempfile::tempdir().unwrap();
    let pcap_path = dir.path().join("scan.pcap");
    write_brute_force_pcap(pcap_path.to_str().unwrap());

    let store = setup_store().await;

    let alert_manager = AlertManager::new(
        Box::new(NoopSummarizer),
        Box::new(Arc::clone(&store)),
    );

    let mut detection = DetectionEngine::new();
    detection.register(Box::new(SignatureEngine::with_defaults()));

    let mut flow_tracker = FlowTracker::new();
    let mut source = PcapReplaySource::open(pcap_path.to_str().unwrap()).unwrap();

    while let Ok(Some(pkt)) = source.next_packet().await {
        let snap = flow_tracker.update(&pkt);
        FlowRepository::save(store.as_ref(), &snap.flow).await.unwrap();
        let alerts = detection.run(&snap).await.unwrap();
        for raw in alerts {
            let _ = alert_manager.dispatch(raw, snap.clone()).await;
        }
    }

    // Build the API router and test it
    let state = AppState {
        alerts: Arc::clone(&store) as Arc<dyn vigil::models::AlertRepository>,
        flows: Arc::clone(&store) as Arc<dyn vigil::models::FlowRepository>,
    };
    let app = api::router(state);

    // Health check
    let resp = app
        .clone()
        .oneshot(Request::get("/api/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Alerts endpoint
    let resp = app
        .clone()
        .oneshot(Request::get("/api/alerts").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let alerts: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert!(!alerts.is_empty(), "API should return at least one alert");

    // Flows endpoint
    let resp = app
        .oneshot(Request::get("/api/flows").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let flows: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert!(!flows.is_empty(), "API should return at least one flow");
}
