/// Detection engine — signature matching and statistical anomaly detection.
///
/// `DetectionEngine` is the OCP orchestrator: register any number of `Detector`
/// implementations at startup. Ships with `SignatureEngine` (rule-based) and
/// `AnomalyDetector` (baseline deviation via Welford's algorithm).
use std::collections::HashMap;
use std::sync::Mutex;

use uuid::Uuid;

use crate::models::{
    AlertKind, BoxFuture, Detector, Flow, FlowSnapshot, Protocol, RawAlert,
    Result, Severity, Signature, SignatureCategory,
};

// ---------------------------------------------------------------------------
// SignatureEngine
// ---------------------------------------------------------------------------

pub struct SignatureEngine {
    signatures: Vec<Signature>,
}

impl SignatureEngine {
    pub fn new(signatures: Vec<Signature>) -> Self {
        Self { signatures }
    }

    pub fn with_defaults() -> Self {
        Self {
            signatures: default_signatures(),
        }
    }
}

pub fn default_signatures() -> Vec<Signature> {
    vec![
        Signature {
            signature_id: Uuid::new_v4(),
            name: "Port Scan".into(),
            category: SignatureCategory::PortScan,
            description: "High packet count with near-zero payload indicating port probing".into(),
            severity: Severity::Medium,
            rule: "packet_count >= 20 && avg_packet_len < 10.0".into(),
        },
        Signature {
            signature_id: Uuid::new_v4(),
            name: "SYN Flood".into(),
            category: SignatureCategory::SynFlood,
            description: "TCP SYN flood with no completing handshakes".into(),
            severity: Severity::Critical,
            rule: "tcp && syn_count > 50 && fin_count == 0 && syn_ratio > 0.8".into(),
        },
        Signature {
            signature_id: Uuid::new_v4(),
            name: "DNS Tunneling".into(),
            category: SignatureCategory::DnsTunneling,
            description: "Abnormally large DNS payloads suggesting data exfiltration via DNS".into(),
            severity: Severity::High,
            rule: "udp && port == 53 && avg_packet_len > 200.0".into(),
        },
        Signature {
            signature_id: Uuid::new_v4(),
            name: "Brute Force".into(),
            category: SignatureCategory::BruteForce,
            description: "Repeated small packets to authentication service ports".into(),
            severity: Severity::High,
            rule: "tcp && dst_port in [22,23,3389] && packet_count >= 30 && avg_pkt < 100".into(),
        },
        Signature {
            signature_id: Uuid::new_v4(),
            name: "Data Exfiltration".into(),
            category: SignatureCategory::DataExfiltration,
            description: "Large outbound data transfer exceeding 10 MB threshold".into(),
            severity: Severity::Critical,
            rule: "byte_count > 10_000_000".into(),
        },
    ]
}

impl SignatureEngine {
    fn matches(sig: &Signature, flow: &Flow) -> bool {
        match sig.category {
            SignatureCategory::PortScan => {
                // High packet count with near-zero payload — probing behavior
                flow.packet_count >= 20
                    && flow.avg_packet_len < 10.0
            }
            SignatureCategory::SynFlood => {
                // SYN count dominates total packet count
                flow.protocol == Protocol::Tcp
                    && flow.syn_count > 50
                    && flow.fin_count == 0
                    && (flow.syn_count as f64 / flow.packet_count.max(1) as f64) > 0.8
            }
            SignatureCategory::DnsTunneling => {
                // UDP port 53 with abnormally large payloads
                flow.protocol == Protocol::Udp
                    && (flow.src_port == 53 || flow.dst_port == 53)
                    && flow.avg_packet_len > 200.0
            }
            SignatureCategory::BruteForce => {
                // Many small packets to well-known auth service ports
                let auth_port = matches!(flow.dst_port, 22 | 23 | 3389);
                flow.protocol == Protocol::Tcp
                    && auth_port
                    && flow.packet_count >= 30
                    && flow.avg_packet_len < 100.0
            }
            SignatureCategory::DataExfiltration => {
                // Large outbound byte volume
                flow.byte_count > 10_000_000
            }
            SignatureCategory::Other => false,
        }
    }
}

impl Detector for SignatureEngine {
    fn inspect<'a>(&'a self, snap: &'a FlowSnapshot) -> BoxFuture<'a, Result<Option<RawAlert>>> {
        Box::pin(async move {
            for sig in &self.signatures {
                if Self::matches(sig, &snap.flow) {
                    return Ok(Some(RawAlert {
                        flow_id: snap.flow.flow_id,
                        kind: AlertKind::SignatureMatch,
                        severity: sig.severity,
                        title: sig.name.clone(),
                        detail: format!(
                            "{} (rule: {}, flow packets: {}, bytes: {})",
                            sig.description, sig.rule, snap.flow.packet_count, snap.flow.byte_count
                        ),
                    }));
                }
            }
            Ok(None)
        })
    }
}

// ---------------------------------------------------------------------------
// AnomalyDetector
// ---------------------------------------------------------------------------

/// Running statistics tracked per flow using Welford's online algorithm.
struct Baseline {
    packet_rate_mean: f64,
    packet_rate_m2: f64,
    pkt_len_mean: f64,
    pkt_len_m2: f64,
    sample_count: u64,
}

impl Baseline {
    fn new() -> Self {
        Self {
            packet_rate_mean: 0.0,
            packet_rate_m2: 0.0,
            pkt_len_mean: 0.0,
            pkt_len_m2: 0.0,
            sample_count: 0,
        }
    }

    fn update(&mut self, packet_rate: f64, avg_pkt_len: f64) {
        self.sample_count += 1;
        let n = self.sample_count as f64;

        let delta_pr = packet_rate - self.packet_rate_mean;
        self.packet_rate_mean += delta_pr / n;
        let delta_pr2 = packet_rate - self.packet_rate_mean;
        self.packet_rate_m2 += delta_pr * delta_pr2;

        let delta_pl = avg_pkt_len - self.pkt_len_mean;
        self.pkt_len_mean += delta_pl / n;
        let delta_pl2 = avg_pkt_len - self.pkt_len_mean;
        self.pkt_len_m2 += delta_pl * delta_pl2;
    }

    fn packet_rate_stddev(&self) -> f64 {
        if self.sample_count < 2 {
            return 0.0;
        }
        (self.packet_rate_m2 / (self.sample_count - 1) as f64).sqrt()
    }

    fn pkt_len_stddev(&self) -> f64 {
        if self.sample_count < 2 {
            return 0.0;
        }
        (self.pkt_len_m2 / (self.sample_count - 1) as f64).sqrt()
    }
}

pub struct AnomalyDetector {
    sigma_threshold: f64,
    baselines: Mutex<HashMap<Uuid, Baseline>>,
}

impl AnomalyDetector {
    pub fn new(sigma_threshold: f64) -> Self {
        Self {
            sigma_threshold,
            baselines: Mutex::new(HashMap::new()),
        }
    }

    fn compute_packet_rate(flow: &Flow) -> f64 {
        let duration_s = (flow.last_seen_at - flow.started_at)
            .num_milliseconds()
            .max(1) as f64
            / 1000.0;
        flow.packet_count as f64 / duration_s
    }

    fn z_score(value: f64, mean: f64, stddev: f64) -> f64 {
        if stddev < f64::EPSILON {
            return 0.0;
        }
        (value - mean).abs() / stddev
    }
}

impl Detector for AnomalyDetector {
    fn inspect<'a>(&'a self, snap: &'a FlowSnapshot) -> BoxFuture<'a, Result<Option<RawAlert>>> {
        Box::pin(async move {
        let flow = &snap.flow;
        let packet_rate = Self::compute_packet_rate(flow);
        let avg_pkt_len = flow.avg_packet_len;

        let mut baselines = self.baselines.lock().unwrap();
        let baseline = baselines
            .entry(flow.flow_id)
            .or_insert_with(Baseline::new);

        // Need enough samples before flagging deviations
        let result = if baseline.sample_count >= 5 {
            let pr_z = Self::z_score(packet_rate, baseline.packet_rate_mean, baseline.packet_rate_stddev());
            let pl_z = Self::z_score(avg_pkt_len, baseline.pkt_len_mean, baseline.pkt_len_stddev());

            if pr_z > self.sigma_threshold {
                Some(RawAlert {
                    flow_id: flow.flow_id,
                    kind: AlertKind::AnomalyDetected,
                    severity: Severity::Medium,
                    title: "Anomalous packet rate".into(),
                    detail: format!(
                        "packet_rate={:.1}/s, baseline={:.1}/s, z={:.2}",
                        packet_rate, baseline.packet_rate_mean, pr_z
                    ),
                })
            } else if pl_z > self.sigma_threshold {
                Some(RawAlert {
                    flow_id: flow.flow_id,
                    kind: AlertKind::AnomalyDetected,
                    severity: Severity::Medium,
                    title: "Anomalous packet size".into(),
                    detail: format!(
                        "avg_pkt_len={:.1}, baseline={:.1}, z={:.2}",
                        avg_pkt_len, baseline.pkt_len_mean, pl_z
                    ),
                })
            } else {
                None
            }
        } else {
            None
        };

            baseline.update(packet_rate, avg_pkt_len);
            Ok(result)
        })
    }
}

// ---------------------------------------------------------------------------
// DetectionEngine
// ---------------------------------------------------------------------------

pub struct DetectionEngine {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectionEngine {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    pub fn register(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
    }

    pub async fn run(&self, snap: &FlowSnapshot) -> Result<Vec<RawAlert>> {
        let mut alerts = Vec::new();
        for detector in &self.detectors {
            if let Some(alert) = detector.inspect(snap).await? {
                alerts.push(alert);
            }
        }
        Ok(alerts)
    }
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{FlowSnapshot, Protocol};
    use chrono::{Duration, TimeZone, Utc};
    use std::net::IpAddr;

    fn make_flow(overrides: impl FnOnce(&mut Flow)) -> Flow {
        let mut flow = Flow {
            flow_id: Uuid::new_v4(),
            src_ip: IpAddr::from([10, 0, 0, 1]),
            dst_ip: IpAddr::from([10, 0, 0, 2]),
            src_port: 12345,
            dst_port: 80,
            protocol: Protocol::Tcp,
            started_at: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap(),
            last_seen_at: Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 10).unwrap(),
            packet_count: 5,
            byte_count: 500,
            avg_packet_len: 100.0,
            avg_inter_arrival_ms: 50.0,
            syn_count: 0,
            fin_count: 0,
        };
        overrides(&mut flow);
        flow
    }

    fn snap(flow: Flow) -> FlowSnapshot {
        FlowSnapshot {
            captured_at: Utc::now(),
            flow,
        }
    }

    fn make_signature(category: SignatureCategory, severity: Severity) -> Signature {
        Signature {
            signature_id: Uuid::new_v4(),
            name: format!("{:?} rule", category),
            category,
            description: format!("Detects {:?}", category),
            severity,
            rule: "test-rule".into(),
        }
    }

    // -- SignatureEngine tests --

    #[tokio::test]
    async fn signature_detects_port_scan() {
        let engine = SignatureEngine::new(vec![
            make_signature(SignatureCategory::PortScan, Severity::High),
        ]);

        let flow = make_flow(|f| {
            f.packet_count = 25;
            f.avg_packet_len = 0.0; // empty probes
        });

        let result = engine.inspect(&snap(flow)).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().kind, AlertKind::SignatureMatch);
    }

    #[tokio::test]
    async fn signature_ignores_normal_traffic() {
        let engine = SignatureEngine::new(vec![
            make_signature(SignatureCategory::PortScan, Severity::High),
        ]);

        let flow = make_flow(|f| {
            f.packet_count = 10;
            f.avg_packet_len = 500.0;
        });

        let result = engine.inspect(&snap(flow)).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn signature_detects_syn_flood() {
        let engine = SignatureEngine::new(vec![
            make_signature(SignatureCategory::SynFlood, Severity::Critical),
        ]);

        let flow = make_flow(|f| {
            f.packet_count = 100;
            f.syn_count = 95;
            f.fin_count = 0;
        });

        let result = engine.inspect(&snap(flow)).await.unwrap();
        assert!(result.is_some());
        let alert = result.unwrap();
        assert_eq!(alert.severity, Severity::Critical);
    }

    #[tokio::test]
    async fn signature_detects_dns_tunneling() {
        let engine = SignatureEngine::new(vec![
            make_signature(SignatureCategory::DnsTunneling, Severity::High),
        ]);

        let flow = make_flow(|f| {
            f.protocol = Protocol::Udp;
            f.dst_port = 53;
            f.avg_packet_len = 300.0;
        });

        let result = engine.inspect(&snap(flow)).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn signature_detects_brute_force() {
        let engine = SignatureEngine::new(vec![
            make_signature(SignatureCategory::BruteForce, Severity::High),
        ]);

        let flow = make_flow(|f| {
            f.dst_port = 22;
            f.packet_count = 50;
            f.avg_packet_len = 40.0;
        });

        let result = engine.inspect(&snap(flow)).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn signature_detects_data_exfiltration() {
        let engine = SignatureEngine::new(vec![
            make_signature(SignatureCategory::DataExfiltration, Severity::Critical),
        ]);

        let flow = make_flow(|f| {
            f.byte_count = 50_000_000;
        });

        let result = engine.inspect(&snap(flow)).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn signature_no_match_returns_none() {
        let engine = SignatureEngine::new(vec![
            make_signature(SignatureCategory::SynFlood, Severity::Critical),
            make_signature(SignatureCategory::PortScan, Severity::High),
        ]);

        let flow = make_flow(|_| {}); // default flow is benign
        let result = engine.inspect(&snap(flow)).await.unwrap();
        assert!(result.is_none());
    }

    // -- AnomalyDetector tests --

    #[tokio::test]
    async fn anomaly_no_alert_during_warmup() {
        let detector = AnomalyDetector::new(3.0);
        let flow = make_flow(|_| {});

        // First 5 observations are warmup — should never alert
        for _ in 0..5 {
            let result = detector.inspect(&snap(flow.clone())).await.unwrap();
            assert!(result.is_none());
        }
    }

    #[tokio::test]
    async fn anomaly_alerts_on_spike() {
        let detector = AnomalyDetector::new(2.0);
        let flow_id = Uuid::new_v4();
        let t0 = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

        // Build a stable baseline: ~10 pkt/s with small natural variance
        let counts = [98, 102, 99, 101, 100, 97, 103, 100, 99, 101u64];
        for count in counts {
            let flow = make_flow(|f| {
                f.flow_id = flow_id;
                f.started_at = t0;
                f.last_seen_at = t0 + Duration::seconds(10);
                f.packet_count = count;
                f.byte_count = count * 100;
                f.avg_packet_len = 100.0;
            });
            detector.inspect(&snap(flow)).await.unwrap();
        }

        // Now spike the packet rate 10x
        let spike = make_flow(|f| {
            f.flow_id = flow_id;
            f.started_at = t0;
            f.last_seen_at = t0 + Duration::seconds(10);
            f.packet_count = 1000; // 100 pkt/s vs baseline ~10 pkt/s
            f.byte_count = 100_000;
            f.avg_packet_len = 100.0;
        });

        let result = detector.inspect(&snap(spike)).await.unwrap();
        assert!(result.is_some());
        let alert = result.unwrap();
        assert_eq!(alert.kind, AlertKind::AnomalyDetected);
        assert!(alert.title.contains("packet rate"));
    }

    #[tokio::test]
    async fn anomaly_no_alert_for_stable_traffic() {
        let detector = AnomalyDetector::new(3.0);
        let flow_id = Uuid::new_v4();
        let t0 = Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();

        for _ in 0..20 {
            let flow = make_flow(|f| {
                f.flow_id = flow_id;
                f.started_at = t0;
                f.last_seen_at = t0 + Duration::seconds(10);
                f.packet_count = 100;
                f.avg_packet_len = 100.0;
            });
            let result = detector.inspect(&snap(flow)).await.unwrap();
            assert!(result.is_none());
        }
    }

    // -- DetectionEngine tests --

    #[tokio::test]
    async fn engine_collects_alerts_from_multiple_detectors() {
        let mut engine = DetectionEngine::new();

        engine.register(Box::new(SignatureEngine::new(vec![
            make_signature(SignatureCategory::PortScan, Severity::High),
        ])));
        engine.register(Box::new(SignatureEngine::new(vec![
            make_signature(SignatureCategory::DataExfiltration, Severity::Critical),
        ])));

        // Flow that triggers both rules
        let flow = make_flow(|f| {
            f.packet_count = 25;
            f.avg_packet_len = 0.0;
            f.byte_count = 50_000_000;
        });

        let alerts = engine.run(&snap(flow)).await.unwrap();
        assert_eq!(alerts.len(), 2);
    }

    #[tokio::test]
    async fn engine_returns_empty_when_no_detectors() {
        let engine = DetectionEngine::new();
        let flow = make_flow(|_| {});
        let alerts = engine.run(&snap(flow)).await.unwrap();
        assert!(alerts.is_empty());
    }

    #[tokio::test]
    async fn engine_returns_empty_when_nothing_matches() {
        let mut engine = DetectionEngine::new();
        engine.register(Box::new(SignatureEngine::new(vec![
            make_signature(SignatureCategory::SynFlood, Severity::Critical),
        ])));

        let flow = make_flow(|_| {}); // benign
        let alerts = engine.run(&snap(flow)).await.unwrap();
        assert!(alerts.is_empty());
    }
}
