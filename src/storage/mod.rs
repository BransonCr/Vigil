/// SQLite persistence for alerts and flows via sqlx.
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::models::{
    Alert, AlertFilter, AlertKind, AlertRepository, BoxFuture, Flow,
    FlowRepository, Protocol, Result, Severity, VigilError,
};

pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn connect(path: &str) -> Result<Self> {
        let opts = SqliteConnectOptions::from_str(path)
            .map_err(|e| VigilError::Storage(e))?
            .create_if_missing(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(opts)
            .await
            .map_err(|e| VigilError::Storage(e))?;

        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                flow_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                detail TEXT NOT NULL,
                llm_summary TEXT
            )",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS flows (
                flow_id TEXT PRIMARY KEY,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                started_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                packet_count INTEGER NOT NULL,
                byte_count INTEGER NOT NULL,
                avg_packet_len REAL NOT NULL,
                avg_inter_arrival_ms REAL NOT NULL,
                syn_count INTEGER NOT NULL,
                fin_count INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Enum serialization helpers
// ---------------------------------------------------------------------------

fn alert_kind_to_str(kind: AlertKind) -> &'static str {
    match kind {
        AlertKind::SignatureMatch => "signature_match",
        AlertKind::AnomalyDetected => "anomaly_detected",
    }
}

fn str_to_alert_kind(s: &str) -> std::result::Result<AlertKind, VigilError> {
    match s {
        "signature_match" => Ok(AlertKind::SignatureMatch),
        "anomaly_detected" => Ok(AlertKind::AnomalyDetected),
        other => Err(VigilError::Internal(format!("unknown alert kind: {other}"))),
    }
}

fn severity_to_str(sev: Severity) -> &'static str {
    match sev {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn str_to_severity(s: &str) -> std::result::Result<Severity, VigilError> {
    match s {
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        other => Err(VigilError::Internal(format!("unknown severity: {other}"))),
    }
}

fn protocol_to_str(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Icmp => "icmp",
        Protocol::Other(_) => "other",
    }
}

fn str_to_protocol(s: &str) -> Protocol {
    match s {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        _ => Protocol::Other(0),
    }
}

// ---------------------------------------------------------------------------
// Row → domain type helpers
// ---------------------------------------------------------------------------

fn row_to_alert(row: &sqlx::sqlite::SqliteRow) -> std::result::Result<Alert, VigilError> {
    let alert_id: String = row.get("alert_id");
    let flow_id: String = row.get("flow_id");
    let created_at: String = row.get("created_at");
    let kind: String = row.get("kind");
    let severity: String = row.get("severity");

    Ok(Alert {
        alert_id: Uuid::parse_str(&alert_id)
            .map_err(|e| VigilError::Internal(e.to_string()))?,
        flow_id: Uuid::parse_str(&flow_id)
            .map_err(|e| VigilError::Internal(e.to_string()))?,
        created_at: DateTime::parse_from_rfc3339(&created_at)
            .map_err(|e| VigilError::Internal(e.to_string()))?
            .with_timezone(&Utc),
        kind: str_to_alert_kind(&kind)?,
        severity: str_to_severity(&severity)?,
        title: row.get("title"),
        detail: row.get("detail"),
        llm_summary: row.get("llm_summary"),
    })
}

fn row_to_flow(row: &sqlx::sqlite::SqliteRow) -> std::result::Result<Flow, VigilError> {
    let flow_id: String = row.get("flow_id");
    let src_ip: String = row.get("src_ip");
    let dst_ip: String = row.get("dst_ip");
    let protocol: String = row.get("protocol");
    let started_at: String = row.get("started_at");
    let last_seen_at: String = row.get("last_seen_at");

    Ok(Flow {
        flow_id: Uuid::parse_str(&flow_id)
            .map_err(|e| VigilError::Internal(e.to_string()))?,
        src_ip: IpAddr::from_str(&src_ip)
            .map_err(|e| VigilError::Internal(e.to_string()))?,
        dst_ip: IpAddr::from_str(&dst_ip)
            .map_err(|e| VigilError::Internal(e.to_string()))?,
        src_port: row.get::<i32, _>("src_port") as u16,
        dst_port: row.get::<i32, _>("dst_port") as u16,
        protocol: str_to_protocol(&protocol),
        started_at: DateTime::parse_from_rfc3339(&started_at)
            .map_err(|e| VigilError::Internal(e.to_string()))?
            .with_timezone(&Utc),
        last_seen_at: DateTime::parse_from_rfc3339(&last_seen_at)
            .map_err(|e| VigilError::Internal(e.to_string()))?
            .with_timezone(&Utc),
        packet_count: row.get::<i64, _>("packet_count") as u64,
        byte_count: row.get::<i64, _>("byte_count") as u64,
        avg_packet_len: row.get("avg_packet_len"),
        avg_inter_arrival_ms: row.get("avg_inter_arrival_ms"),
        syn_count: row.get::<i32, _>("syn_count") as u32,
        fin_count: row.get::<i32, _>("fin_count") as u32,
    })
}

// ---------------------------------------------------------------------------
// AlertRepository
// ---------------------------------------------------------------------------

impl AlertRepository for SqliteStore {
    fn save<'a>(&'a self, alert: &'a Alert) -> BoxFuture<'a, Result<Uuid>> {
        Box::pin(async move {
            sqlx::query(
                "INSERT INTO alerts (alert_id, flow_id, created_at, kind, severity, title, detail, llm_summary)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(alert.alert_id.to_string())
            .bind(alert.flow_id.to_string())
            .bind(alert.created_at.to_rfc3339())
            .bind(alert_kind_to_str(alert.kind))
            .bind(severity_to_str(alert.severity))
            .bind(&alert.title)
            .bind(&alert.detail)
            .bind(&alert.llm_summary)
            .execute(&self.pool)
            .await?;

            Ok(alert.alert_id)
        })
    }

    fn find_by_id<'a>(&'a self, id: Uuid) -> BoxFuture<'a, Result<Option<Alert>>> {
        Box::pin(async move {
            let row = sqlx::query("SELECT * FROM alerts WHERE alert_id = ?")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await?;

            match row {
                Some(ref r) => Ok(Some(row_to_alert(r)?)),
                None => Ok(None),
            }
        })
    }

    fn query<'a>(&'a self, filter: &'a AlertFilter) -> BoxFuture<'a, Result<Vec<Alert>>> {
        Box::pin(async move {
            let mut sql = String::from("SELECT * FROM alerts WHERE 1=1");
            let mut binds_severity: Option<String> = None;
            let mut binds_kind: Option<String> = None;

            if let Some(sev) = filter.severity {
                sql.push_str(" AND severity = ?");
                binds_severity = Some(severity_to_str(sev).to_string());
            }
            if let Some(kind) = filter.kind {
                sql.push_str(" AND kind = ?");
                binds_kind = Some(alert_kind_to_str(kind).to_string());
            }

            sql.push_str(" ORDER BY created_at DESC");

            let limit = filter.limit.unwrap_or(100);
            let offset = filter.offset.unwrap_or(0);
            sql.push_str(" LIMIT ? OFFSET ?");

            let mut q = sqlx::query(&sql);
            if let Some(ref s) = binds_severity {
                q = q.bind(s);
            }
            if let Some(ref k) = binds_kind {
                q = q.bind(k);
            }
            q = q.bind(limit).bind(offset);

            let rows = q.fetch_all(&self.pool).await?;
            rows.iter().map(row_to_alert).collect()
        })
    }
}

// ---------------------------------------------------------------------------
// FlowRepository
// ---------------------------------------------------------------------------

impl FlowRepository for SqliteStore {
    fn save<'a>(&'a self, flow: &'a Flow) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            sqlx::query(
                "INSERT OR REPLACE INTO flows
                 (flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
                  started_at, last_seen_at, packet_count, byte_count,
                  avg_packet_len, avg_inter_arrival_ms, syn_count, fin_count)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(flow.flow_id.to_string())
            .bind(flow.src_ip.to_string())
            .bind(flow.dst_ip.to_string())
            .bind(flow.src_port as i32)
            .bind(flow.dst_port as i32)
            .bind(protocol_to_str(flow.protocol))
            .bind(flow.started_at.to_rfc3339())
            .bind(flow.last_seen_at.to_rfc3339())
            .bind(flow.packet_count as i64)
            .bind(flow.byte_count as i64)
            .bind(flow.avg_packet_len)
            .bind(flow.avg_inter_arrival_ms)
            .bind(flow.syn_count as i32)
            .bind(flow.fin_count as i32)
            .execute(&self.pool)
            .await?;

            Ok(())
        })
    }

    fn find_by_id<'a>(&'a self, id: Uuid) -> BoxFuture<'a, Result<Option<Flow>>> {
        Box::pin(async move {
            let row = sqlx::query("SELECT * FROM flows WHERE flow_id = ?")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await?;

            match row {
                Some(ref r) => Ok(Some(row_to_flow(r)?)),
                None => Ok(None),
            }
        })
    }

    fn list<'a>(&'a self, limit: i64, offset: i64) -> BoxFuture<'a, Result<Vec<Flow>>> {
        Box::pin(async move {
            let rows = sqlx::query(
                "SELECT * FROM flows ORDER BY last_seen_at DESC LIMIT ? OFFSET ?",
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;

            rows.iter().map(row_to_flow).collect()
        })
    }
}

// ---------------------------------------------------------------------------
// Arc delegation — allows Arc<SqliteStore> to be used as dyn repository
// ---------------------------------------------------------------------------

impl AlertRepository for Arc<SqliteStore> {
    fn save<'a>(&'a self, alert: &'a Alert) -> BoxFuture<'a, Result<Uuid>> {
        AlertRepository::save(self.as_ref(), alert)
    }

    fn find_by_id<'a>(&'a self, id: Uuid) -> BoxFuture<'a, Result<Option<Alert>>> {
        AlertRepository::find_by_id(self.as_ref(), id)
    }

    fn query<'a>(&'a self, filter: &'a AlertFilter) -> BoxFuture<'a, Result<Vec<Alert>>> {
        AlertRepository::query(self.as_ref(), filter)
    }
}

impl FlowRepository for Arc<SqliteStore> {
    fn save<'a>(&'a self, flow: &'a Flow) -> BoxFuture<'a, Result<()>> {
        FlowRepository::save(self.as_ref(), flow)
    }

    fn find_by_id<'a>(&'a self, id: Uuid) -> BoxFuture<'a, Result<Option<Flow>>> {
        FlowRepository::find_by_id(self.as_ref(), id)
    }

    fn list<'a>(&'a self, limit: i64, offset: i64) -> BoxFuture<'a, Result<Vec<Flow>>> {
        FlowRepository::list(self.as_ref(), limit, offset)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AlertKind, Protocol, Severity};
    use chrono::{TimeZone, Utc};

    async fn test_store() -> SqliteStore {
        let store = SqliteStore::connect("sqlite::memory:").await.unwrap();
        store.migrate().await.unwrap();
        store
    }

    fn sample_alert(severity: Severity, kind: AlertKind) -> Alert {
        Alert {
            alert_id: Uuid::new_v4(),
            flow_id: Uuid::new_v4(),
            created_at: Utc::now(),
            kind,
            severity,
            title: "Test alert".into(),
            detail: "Something suspicious happened".into(),
            llm_summary: Some("An attacker did a thing.".into()),
        }
    }

    fn sample_flow() -> Flow {
        Flow {
            flow_id: Uuid::new_v4(),
            src_ip: IpAddr::from([10, 0, 0, 1]),
            dst_ip: IpAddr::from([10, 0, 0, 2]),
            src_port: 54321,
            dst_port: 80,
            protocol: Protocol::Tcp,
            started_at: Utc.with_ymd_and_hms(2025, 6, 15, 14, 0, 0).unwrap(),
            last_seen_at: Utc.with_ymd_and_hms(2025, 6, 15, 14, 0, 30).unwrap(),
            packet_count: 150,
            byte_count: 45000,
            avg_packet_len: 300.0,
            avg_inter_arrival_ms: 200.0,
            syn_count: 1,
            fin_count: 1,
        }
    }

    // -- Alert tests --

    #[tokio::test]
    async fn alert_save_and_find_by_id() {
        let store = test_store().await;
        let alert = sample_alert(Severity::High, AlertKind::SignatureMatch);
        let id = AlertRepository::save(&store, &alert).await.unwrap();

        let found = AlertRepository::find_by_id(&store, id).await.unwrap();
        assert!(found.is_some());

        let found = found.unwrap();
        assert_eq!(found.alert_id, alert.alert_id);
        assert_eq!(found.severity, Severity::High);
        assert_eq!(found.kind, AlertKind::SignatureMatch);
        assert_eq!(found.title, "Test alert");
        assert_eq!(found.llm_summary, Some("An attacker did a thing.".into()));
    }

    #[tokio::test]
    async fn alert_find_by_id_returns_none_for_missing() {
        let store = test_store().await;
        let found = AlertRepository::find_by_id(&store, Uuid::new_v4()).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn alert_query_no_filter() {
        let store = test_store().await;

        for _ in 0..3 {
            let alert = sample_alert(Severity::Medium, AlertKind::AnomalyDetected);
            AlertRepository::save(&store, &alert).await.unwrap();
        }

        let filter = AlertFilter::default();
        let results = AlertRepository::query(&store, &filter).await.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn alert_query_filter_by_severity() {
        let store = test_store().await;

        AlertRepository::save(&store, &sample_alert(Severity::Low, AlertKind::SignatureMatch)).await.unwrap();
        AlertRepository::save(&store, &sample_alert(Severity::High, AlertKind::SignatureMatch)).await.unwrap();
        AlertRepository::save(&store, &sample_alert(Severity::High, AlertKind::AnomalyDetected)).await.unwrap();

        let filter = AlertFilter {
            severity: Some(Severity::High),
            ..Default::default()
        };
        let results = AlertRepository::query(&store, &filter).await.unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|a| a.severity == Severity::High));
    }

    #[tokio::test]
    async fn alert_query_filter_by_kind() {
        let store = test_store().await;

        AlertRepository::save(&store, &sample_alert(Severity::Medium, AlertKind::SignatureMatch)).await.unwrap();
        AlertRepository::save(&store, &sample_alert(Severity::Medium, AlertKind::AnomalyDetected)).await.unwrap();
        AlertRepository::save(&store, &sample_alert(Severity::Medium, AlertKind::AnomalyDetected)).await.unwrap();

        let filter = AlertFilter {
            kind: Some(AlertKind::AnomalyDetected),
            ..Default::default()
        };
        let results = AlertRepository::query(&store, &filter).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn alert_query_with_limit_and_offset() {
        let store = test_store().await;

        for _ in 0..5 {
            AlertRepository::save(&store, &sample_alert(Severity::Low, AlertKind::SignatureMatch)).await.unwrap();
        }

        let filter = AlertFilter {
            limit: Some(2),
            offset: Some(1),
            ..Default::default()
        };
        let results = AlertRepository::query(&store, &filter).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn alert_without_llm_summary() {
        let store = test_store().await;
        let mut alert = sample_alert(Severity::Low, AlertKind::SignatureMatch);
        alert.llm_summary = None;

        let id = AlertRepository::save(&store, &alert).await.unwrap();
        let found = AlertRepository::find_by_id(&store, id).await.unwrap().unwrap();
        assert!(found.llm_summary.is_none());
    }

    // -- Flow tests --

    #[tokio::test]
    async fn flow_save_and_find_by_id() {
        let store = test_store().await;
        let flow = sample_flow();

        FlowRepository::save(&store, &flow).await.unwrap();
        let found = FlowRepository::find_by_id(&store, flow.flow_id).await.unwrap();

        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.flow_id, flow.flow_id);
        assert_eq!(found.src_ip, flow.src_ip);
        assert_eq!(found.dst_ip, flow.dst_ip);
        assert_eq!(found.src_port, 54321);
        assert_eq!(found.dst_port, 80);
        assert_eq!(found.protocol, Protocol::Tcp);
        assert_eq!(found.packet_count, 150);
        assert_eq!(found.byte_count, 45000);
        assert_eq!(found.syn_count, 1);
        assert_eq!(found.fin_count, 1);
    }

    #[tokio::test]
    async fn flow_find_by_id_returns_none_for_missing() {
        let store = test_store().await;
        let found = FlowRepository::find_by_id(&store, Uuid::new_v4()).await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn flow_upsert_updates_existing() {
        let store = test_store().await;
        let mut flow = sample_flow();

        FlowRepository::save(&store, &flow).await.unwrap();

        flow.packet_count = 300;
        flow.byte_count = 90000;
        FlowRepository::save(&store, &flow).await.unwrap();

        let found = FlowRepository::find_by_id(&store, flow.flow_id).await.unwrap().unwrap();
        assert_eq!(found.packet_count, 300);
        assert_eq!(found.byte_count, 90000);
    }

    #[tokio::test]
    async fn flow_list_with_pagination() {
        let store = test_store().await;

        for _ in 0..5 {
            FlowRepository::save(&store, &sample_flow()).await.unwrap();
        }

        let all = FlowRepository::list(&store, 100, 0).await.unwrap();
        assert_eq!(all.len(), 5);

        let page = FlowRepository::list(&store, 2, 1).await.unwrap();
        assert_eq!(page.len(), 2);
    }

    // -- Enum roundtrip tests --

    #[test]
    fn alert_kind_roundtrip() {
        for kind in [AlertKind::SignatureMatch, AlertKind::AnomalyDetected] {
            let s = alert_kind_to_str(kind);
            assert_eq!(str_to_alert_kind(s).unwrap(), kind);
        }
    }

    #[test]
    fn severity_roundtrip() {
        for sev in [Severity::Low, Severity::Medium, Severity::High, Severity::Critical] {
            let s = severity_to_str(sev);
            assert_eq!(str_to_severity(s).unwrap(), sev);
        }
    }

    #[test]
    fn protocol_roundtrip() {
        for proto in [Protocol::Tcp, Protocol::Udp, Protocol::Icmp] {
            let s = protocol_to_str(proto);
            assert_eq!(str_to_protocol(s), proto);
        }
    }
}
