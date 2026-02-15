use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use vigil::alert::AlertManager;
use vigil::api::{self, AppState};
use vigil::capture::{PacketCapture, PcapReplaySource};
use vigil::detection::{AnomalyDetector, DetectionEngine, SignatureEngine};
use vigil::enrichment::{LlmEnrichmentService, NoopSummarizer};
use vigil::flow::FlowTracker;
use vigil::models::{FlowRepository, PacketSource, SummaryProvider};
use vigil::storage::SqliteStore;
use vigil::tui::state::{LiveCounters, ShutdownSignal};

#[tokio::main]
async fn main() {
    let tui_enabled = env::var("VIGIL_TUI").is_ok_and(|v| v == "1" || v == "true");

    let env_filter = || {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
    };

    if tui_enabled {
        // When TUI is active, redirect tracing to a log file so it doesn't
        // corrupt the terminal output. Use VIGIL_LOG or default to /tmp/vigil.log
        // to avoid permission conflicts between sudo and non-sudo runs.
        let log_path = env::var("VIGIL_LOG").unwrap_or_else(|_| "/tmp/vigil.log".into());
        let log_dir = std::path::Path::new(&log_path)
            .parent()
            .unwrap_or(std::path::Path::new("/tmp"));
        let log_file = std::path::Path::new(&log_path)
            .file_name()
            .unwrap_or(std::ffi::OsStr::new("vigil.log"));
        let file_appender = tracing_appender::rolling::never(log_dir, log_file);
        tracing_subscriber::fmt()
            .with_env_filter(env_filter())
            .with_writer(file_appender)
            .with_ansi(false)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter())
            .init();
    }

    if let Err(e) = run(tui_enabled).await {
        tracing::error!("fatal: {e}");
        std::process::exit(1);
    }
}

async fn run(tui_enabled: bool) -> vigil::models::Result<()> {
    let db_path = env::var("VIGIL_DB_PATH").unwrap_or_else(|_| "vigil.db".into());
    let api_addr: SocketAddr = env::var("VIGIL_API_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:3000".into())
        .parse()
        .expect("VIGIL_API_ADDR must be a valid socket address");
    let pcap_file = env::var("VIGIL_PCAP").ok();
    let interface = env::var("VIGIL_INTERFACE").unwrap_or_else(|_| {
        pcap::Device::lookup()
            .ok()
            .flatten()
            .map(|d| d.name)
            .unwrap_or_else(|| "eth0".into())
    });
    let api_key = env::var("ANTHROPIC_API_KEY").ok();

    // --- Storage ---
    tracing::info!(db = %db_path, "connecting to database");
    let store = Arc::new(SqliteStore::connect(&db_path).await?);
    store.migrate().await?;

    // --- Enrichment ---
    let summarizer: Box<dyn SummaryProvider> = match api_key {
        Some(key) => {
            tracing::info!("LLM enrichment enabled");
            Box::new(LlmEnrichmentService::new(key))
        }
        None => {
            tracing::warn!("ANTHROPIC_API_KEY not set — using noop summarizer");
            Box::new(NoopSummarizer)
        }
    };

    // --- Alert manager ---
    let alert_manager = AlertManager::new(summarizer, Box::new(Arc::clone(&store)));

    // --- Detection engine ---
    let mut detection = DetectionEngine::new();
    detection.register(Box::new(SignatureEngine::with_defaults()));
    detection.register(Box::new(AnomalyDetector::new(3.0)));
    tracing::info!("detection engine ready (signatures + anomaly detector)");

    // --- Flow tracker ---
    let mut flow_tracker = FlowTracker::new();

    // --- Shared state for TUI ---
    let counters = Arc::new(LiveCounters::new());
    let shutdown = Arc::new(ShutdownSignal::new());

    // --- API server ---
    let state = AppState {
        alerts: Arc::clone(&store) as Arc<dyn vigil::models::AlertRepository>,
        flows: Arc::clone(&store) as Arc<dyn vigil::models::FlowRepository>,
    };

    let api_handle = tokio::spawn(async move {
        tracing::info!(%api_addr, "starting API server");
        if let Err(e) = api::serve(api_addr, state).await {
            tracing::error!("API server error: {e}");
        }
    });

    // --- TUI thread ---
    let tui_handle = if tui_enabled {
        let tui_counters = Arc::clone(&counters);
        let tui_shutdown = Arc::clone(&shutdown);
        let tui_store = Arc::clone(&store);
        let rt_handle = tokio::runtime::Handle::current();

        Some(std::thread::spawn(move || {
            vigil::tui::run_tui(tui_counters, tui_shutdown, tui_store, rt_handle);
        }))
    } else {
        None
    };

    // --- Packet capture loop ---
    if let Some(ref path) = pcap_file {
        tracing::info!(file = %path, "replaying pcap file");
        let mut source = PcapReplaySource::open(path)?;
        run_capture_loop(
            &mut source,
            &mut flow_tracker,
            &detection,
            &alert_manager,
            &store,
            &counters,
            &shutdown,
        )
        .await?;
        tracing::info!("pcap replay finished");
    } else {
        tracing::info!(iface = %interface, "starting live capture");
        let mut source = PacketCapture::open(&interface)?;
        run_capture_loop(
            &mut source,
            &mut flow_tracker,
            &detection,
            &alert_manager,
            &store,
            &counters,
            &shutdown,
        )
        .await?;
    }

    // Wait for TUI thread to finish (if it hasn't already)
    if let Some(handle) = tui_handle {
        // Signal the TUI to quit in case capture ended first (e.g. pcap replay)
        shutdown.request_shutdown();
        let _ = handle.join();
    }

    api_handle.abort();
    Ok(())
}

async fn run_capture_loop<S: PacketSource>(
    source: &mut S,
    flow_tracker: &mut FlowTracker,
    detection: &DetectionEngine,
    alert_manager: &AlertManager,
    flow_store: &Arc<SqliteStore>,
    counters: &LiveCounters,
    shutdown: &ShutdownSignal,
) -> vigil::models::Result<()> {
    loop {
        if shutdown.is_shutdown() {
            tracing::info!("shutdown signal received, stopping capture");
            break;
        }

        let pkt = match source.next_packet().await {
            Ok(Some(pkt)) => pkt,
            Ok(None) => break,
            Err(e) => {
                tracing::warn!("packet read error: {e}");
                continue;
            }
        };

        counters.inc_packets();
        let snap = flow_tracker.update(&pkt);
        counters.set_flows(flow_tracker.flow_count() as u64);

        if let Err(e) = FlowRepository::save(flow_store.as_ref(), &snap.flow).await {
            tracing::warn!("flow persist error: {e}");
        }

        let alerts = detection.run(&snap).await?;

        for raw in alerts {
            tracing::warn!(
                kind = ?raw.kind,
                severity = ?raw.severity,
                title = %raw.title,
                "alert triggered"
            );
            match alert_manager.dispatch(raw, snap.clone()).await {
                Ok(Some(alert)) => {
                    counters.inc_alerts();
                    tracing::info!(
                        id = %alert.alert_id,
                        summary = ?alert.llm_summary,
                        "alert persisted"
                    );
                }
                Ok(None) => tracing::debug!("alert deduplicated"),
                Err(e) => tracing::error!("alert dispatch error: {e}"),
            }
        }

        if counters.packets().is_multiple_of(1000) {
            tracing::info!(
                packets = counters.packets(),
                flows = counters.flows(),
                alerts = counters.alerts(),
                "progress"
            );
        }
    }

    tracing::info!(
        packets = counters.packets(),
        flows = counters.flows(),
        alerts = counters.alerts(),
        "capture complete"
    );
    Ok(())
}
