pub mod app;
pub mod state;
pub mod ui;

use std::sync::Arc;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event, KeyEventKind};

use crate::models::{AlertFilter, AlertRepository, FlowRepository};
use crate::storage::SqliteStore;

use self::app::App;
use self::state::{LiveCounters, ShutdownSignal};

/// Runs the TUI on the current thread (must NOT be called from a tokio task).
///
/// Uses `rt_handle` to issue async DB queries via `block_on`.
pub fn run_tui(
    counters: Arc<LiveCounters>,
    shutdown: Arc<ShutdownSignal>,
    store: Arc<SqliteStore>,
    rt_handle: tokio::runtime::Handle,
) {
    let mut terminal = ratatui::init();
    let mut app = App::new();
    let mut last_db_refresh = Instant::now();
    let db_interval = Duration::from_millis(500);

    // Initial DB load
    refresh_db_data(&mut app, &store, &rt_handle);

    while app.running && !shutdown.is_shutdown() {
        // Render
        let counters_ref = &counters;
        terminal
            .draw(|frame| ui::render(frame, &mut app, counters_ref))
            .expect("failed to draw frame");

        // Poll for input
        if event::poll(Duration::from_millis(200)).unwrap_or(false)
            && let Ok(Event::Key(key)) = event::read()
            && key.kind == KeyEventKind::Press
        {
            app.handle_key(key);
        }

        // Periodic DB refresh
        if last_db_refresh.elapsed() >= db_interval {
            refresh_db_data(&mut app, &store, &rt_handle);
            last_db_refresh = Instant::now();
        }
    }

    // Signal capture loop to stop
    shutdown.request_shutdown();
    ratatui::restore();
}

fn refresh_db_data(app: &mut App, store: &Arc<SqliteStore>, handle: &tokio::runtime::Handle) {
    if let Ok(flows) = handle.block_on(FlowRepository::list(store.as_ref(), 200, 0)) {
        app.cached_flows = flows;
    }

    let filter = AlertFilter {
        limit: Some(200),
        ..Default::default()
    };
    if let Ok(alerts) = handle.block_on(AlertRepository::query(store.as_ref(), &filter)) {
        app.cached_alerts = alerts;
    }
}
