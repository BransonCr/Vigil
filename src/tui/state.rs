use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

/// Lock-free counters shared between the capture loop and the TUI thread.
pub struct LiveCounters {
    pub packet_count: AtomicU64,
    pub flow_count: AtomicU64,
    pub alert_count: AtomicU64,
    pub started_at: Instant,
}

impl LiveCounters {
    pub fn new() -> Self {
        Self {
            packet_count: AtomicU64::new(0),
            flow_count: AtomicU64::new(0),
            alert_count: AtomicU64::new(0),
            started_at: Instant::now(),
        }
    }

    pub fn packets(&self) -> u64 {
        self.packet_count.load(Ordering::Relaxed)
    }

    pub fn flows(&self) -> u64 {
        self.flow_count.load(Ordering::Relaxed)
    }

    pub fn alerts(&self) -> u64 {
        self.alert_count.load(Ordering::Relaxed)
    }

    pub fn inc_packets(&self) {
        self.packet_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_flows(&self, count: u64) {
        self.flow_count.store(count, Ordering::Relaxed);
    }

    pub fn inc_alerts(&self) {
        self.alert_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn uptime(&self) -> std::time::Duration {
        self.started_at.elapsed()
    }
}

impl Default for LiveCounters {
    fn default() -> Self {
        Self::new()
    }
}

/// Cooperative shutdown signal shared between TUI and capture loop.
pub struct ShutdownSignal {
    should_quit: AtomicBool,
}

impl ShutdownSignal {
    pub fn new() -> Self {
        Self {
            should_quit: AtomicBool::new(false),
        }
    }

    pub fn request_shutdown(&self) {
        self.should_quit.store(true, Ordering::Relaxed);
    }

    pub fn is_shutdown(&self) -> bool {
        self.should_quit.load(Ordering::Relaxed)
    }
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_counters_increments() {
        let c = LiveCounters::new();
        assert_eq!(c.packets(), 0);
        c.inc_packets();
        c.inc_packets();
        assert_eq!(c.packets(), 2);

        c.set_flows(42);
        assert_eq!(c.flows(), 42);

        c.inc_alerts();
        assert_eq!(c.alerts(), 1);
    }

    #[test]
    fn shutdown_signal_lifecycle() {
        let s = ShutdownSignal::new();
        assert!(!s.is_shutdown());
        s.request_shutdown();
        assert!(s.is_shutdown());
    }
}
