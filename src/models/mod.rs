use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

pub type Result<T> = std::result::Result<T, VigilError>;

#[derive(Debug, thiserror::Error)]
pub enum VigilError {
    #[error("capture: {0}")]
    Capture(String),

    #[error("parse: {0}")]
    Parse(String),

    #[error("storage: {0}")]
    Storage(#[from] sqlx::Error),

    #[error("enrichment: {0}")]
    Enrichment(String),

    #[error("api: {0}")]
    Api(String),

    #[error("{0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertKind {
    SignatureMatch,
    AnomalyDetected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureCategory {
    PortScan,
    SynFlood,
    DnsTunneling,
    BruteForce,
    DataExfiltration,
    Other,
}

// ---------------------------------------------------------------------------
// Packet types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub timestamp: DateTime<Utc>,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub flags: TcpFlags,
    pub payload_len: u32,
    pub ttl: u8,
}

// ---------------------------------------------------------------------------
// Flow types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
}

impl FiveTuple {
    /// Returns a canonical form so (A→B) and (B→A) hash to the same flow.
    pub fn canonical(&self) -> Self {
        if (self.src_ip, self.src_port) <= (self.dst_ip, self.dst_port) {
            *self
        } else {
            Self {
                src_ip: self.dst_ip,
                dst_ip: self.src_ip,
                src_port: self.dst_port,
                dst_port: self.src_port,
                protocol: self.protocol,
            }
        }
    }
}

impl From<&Packet> for FiveTuple {
    fn from(pkt: &Packet) -> Self {
        Self {
            src_ip: pkt.src_ip,
            dst_ip: pkt.dst_ip,
            src_port: pkt.src_port,
            dst_port: pkt.dst_port,
            protocol: pkt.protocol,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub flow_id: Uuid,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub started_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub packet_count: u64,
    pub byte_count: u64,
    pub avg_packet_len: f64,
    pub avg_inter_arrival_ms: f64,
    pub syn_count: u32,
    pub fin_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSnapshot {
    pub flow: Flow,
    pub captured_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Alert types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawAlert {
    pub flow_id: Uuid,
    pub kind: AlertKind,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub alert_id: Uuid,
    pub flow_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub kind: AlertKind,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub llm_summary: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AlertFilter {
    pub severity: Option<Severity>,
    pub kind: Option<AlertKind>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertContext {
    pub alert: RawAlert,
    pub flow_snapshot: FlowSnapshot,
}

// ---------------------------------------------------------------------------
// Signature / Anomaly types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub signature_id: Uuid,
    pub name: String,
    pub category: SignatureCategory,
    pub description: String,
    pub severity: Severity,
    pub rule: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyRecord {
    pub record_id: Uuid,
    pub flow_id: Uuid,
    pub detected_at: DateTime<Utc>,
    pub metric: String,
    pub baseline_value: f64,
    pub observed_value: f64,
    pub deviation_sigma: f64,
}

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

use std::future::Future;
use std::pin::Pin;

/// Convenience alias for a boxed, Send-able future (used by dyn-compatible traits).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[allow(async_fn_in_trait)]
pub trait PacketSource {
    async fn next_packet(&mut self) -> Result<Option<Packet>>;
}

pub trait Detector: Send + Sync {
    fn inspect<'a>(&'a self, flow: &'a FlowSnapshot) -> BoxFuture<'a, Result<Option<RawAlert>>>;
}

pub trait SummaryProvider: Send + Sync {
    fn summarize<'a>(&'a self, ctx: &'a AlertContext) -> BoxFuture<'a, Result<String>>;
}

pub trait AlertRepository: Send + Sync {
    fn save<'a>(&'a self, alert: &'a Alert) -> BoxFuture<'a, Result<Uuid>>;
    fn find_by_id<'a>(&'a self, id: Uuid) -> BoxFuture<'a, Result<Option<Alert>>>;
    fn query<'a>(&'a self, filter: &'a AlertFilter) -> BoxFuture<'a, Result<Vec<Alert>>>;
}

pub trait FlowRepository: Send + Sync {
    fn save<'a>(&'a self, flow: &'a Flow) -> BoxFuture<'a, Result<()>>;
    fn find_by_id<'a>(&'a self, id: Uuid) -> BoxFuture<'a, Result<Option<Flow>>>;
    fn list<'a>(&'a self, limit: i64, offset: i64) -> BoxFuture<'a, Result<Vec<Flow>>>;
}
