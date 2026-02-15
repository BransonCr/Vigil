use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::TableState;

use crate::models::{Alert, Flow};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    Flows,
    Alerts,
    Detail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    Protocol,
    Source,
    Destination,
    Packets,
    Bytes,
    LastSeen,
}

impl SortColumn {
    fn next(self) -> Self {
        match self {
            Self::Protocol => Self::Source,
            Self::Source => Self::Destination,
            Self::Destination => Self::Packets,
            Self::Packets => Self::Bytes,
            Self::Bytes => Self::LastSeen,
            Self::LastSeen => Self::Protocol,
        }
    }
}

impl std::fmt::Display for SortColumn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol => write!(f, "Proto"),
            Self::Source => write!(f, "Source"),
            Self::Destination => write!(f, "Dest"),
            Self::Packets => write!(f, "Pkts"),
            Self::Bytes => write!(f, "Bytes"),
            Self::LastSeen => write!(f, "Last"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailView {
    FlowDetail(usize),
    AlertDetail(usize),
}

pub struct App {
    pub running: bool,
    pub active_panel: Panel,
    pub flows_state: TableState,
    pub alerts_state: TableState,
    pub sort_column: SortColumn,
    pub sort_ascending: bool,
    pub detail_view: Option<DetailView>,
    pub cached_flows: Vec<Flow>,
    pub cached_alerts: Vec<Alert>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        let mut flows_state = TableState::default();
        flows_state.select(Some(0));
        let mut alerts_state = TableState::default();
        alerts_state.select(Some(0));

        Self {
            running: true,
            active_panel: Panel::Flows,
            flows_state,
            alerts_state,
            sort_column: SortColumn::LastSeen,
            sort_ascending: false,
            detail_view: None,
            cached_flows: Vec::new(),
            cached_alerts: Vec::new(),
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        // Global quit
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.running = false;
            return;
        }

        match key.code {
            KeyCode::Char('q') => self.running = false,

            KeyCode::Tab => self.next_panel(),
            KeyCode::BackTab => self.prev_panel(),

            KeyCode::Char('j') | KeyCode::Down => self.move_cursor(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_cursor(-1),

            KeyCode::Enter => self.open_detail(),
            KeyCode::Esc => self.detail_view = None,

            KeyCode::Char('s') => self.sort_column = self.sort_column.next(),
            KeyCode::Char('S') => self.sort_ascending = !self.sort_ascending,

            _ => {}
        }
    }

    fn next_panel(&mut self) {
        self.active_panel = match self.active_panel {
            Panel::Flows => Panel::Alerts,
            Panel::Alerts => {
                if self.detail_view.is_some() {
                    Panel::Detail
                } else {
                    Panel::Flows
                }
            }
            Panel::Detail => Panel::Flows,
        };
    }

    fn prev_panel(&mut self) {
        self.active_panel = match self.active_panel {
            Panel::Flows => {
                if self.detail_view.is_some() {
                    Panel::Detail
                } else {
                    Panel::Alerts
                }
            }
            Panel::Alerts => Panel::Flows,
            Panel::Detail => Panel::Alerts,
        };
    }

    fn move_cursor(&mut self, delta: i32) {
        match self.active_panel {
            Panel::Flows => {
                let len = self.cached_flows.len();
                if len == 0 {
                    return;
                }
                let i = self.flows_state.selected().unwrap_or(0) as i32;
                let next = (i + delta).rem_euclid(len as i32) as usize;
                self.flows_state.select(Some(next));
            }
            Panel::Alerts => {
                let len = self.cached_alerts.len();
                if len == 0 {
                    return;
                }
                let i = self.alerts_state.selected().unwrap_or(0) as i32;
                let next = (i + delta).rem_euclid(len as i32) as usize;
                self.alerts_state.select(Some(next));
            }
            Panel::Detail => {}
        }
    }

    fn open_detail(&mut self) {
        match self.active_panel {
            Panel::Flows => {
                if let Some(i) = self.flows_state.selected()
                    && i < self.cached_flows.len()
                {
                    self.detail_view = Some(DetailView::FlowDetail(i));
                }
            }
            Panel::Alerts => {
                if let Some(i) = self.alerts_state.selected()
                    && i < self.cached_alerts.len()
                {
                    self.detail_view = Some(DetailView::AlertDetail(i));
                }
            }
            Panel::Detail => {}
        }
    }

    /// Returns the sorted flows for display. Sorts in place for efficiency.
    pub fn sorted_flows(&mut self) -> &[Flow] {
        let asc = self.sort_ascending;
        match self.sort_column {
            SortColumn::Protocol => self.cached_flows.sort_by(|a, b| {
                let cmp = format!("{:?}", a.protocol).cmp(&format!("{:?}", b.protocol));
                if asc { cmp } else { cmp.reverse() }
            }),
            SortColumn::Source => self.cached_flows.sort_by(|a, b| {
                let cmp = (a.src_ip, a.src_port).cmp(&(b.src_ip, b.src_port));
                if asc { cmp } else { cmp.reverse() }
            }),
            SortColumn::Destination => self.cached_flows.sort_by(|a, b| {
                let cmp = (a.dst_ip, a.dst_port).cmp(&(b.dst_ip, b.dst_port));
                if asc { cmp } else { cmp.reverse() }
            }),
            SortColumn::Packets => self.cached_flows.sort_by(|a, b| {
                let cmp = a.packet_count.cmp(&b.packet_count);
                if asc { cmp } else { cmp.reverse() }
            }),
            SortColumn::Bytes => self.cached_flows.sort_by(|a, b| {
                let cmp = a.byte_count.cmp(&b.byte_count);
                if asc { cmp } else { cmp.reverse() }
            }),
            SortColumn::LastSeen => self.cached_flows.sort_by(|a, b| {
                let cmp = a.last_seen_at.cmp(&b.last_seen_at);
                if asc { cmp } else { cmp.reverse() }
            }),
        }
        &self.cached_flows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_app_defaults() {
        let app = App::new();
        assert!(app.running);
        assert_eq!(app.active_panel, Panel::Flows);
        assert!(app.detail_view.is_none());
        assert_eq!(app.flows_state.selected(), Some(0));
    }

    #[test]
    fn quit_on_q() {
        let mut app = App::new();
        app.handle_key(KeyEvent::from(KeyCode::Char('q')));
        assert!(!app.running);
    }

    #[test]
    fn tab_cycles_panels() {
        let mut app = App::new();
        assert_eq!(app.active_panel, Panel::Flows);
        app.handle_key(KeyEvent::from(KeyCode::Tab));
        assert_eq!(app.active_panel, Panel::Alerts);
        app.handle_key(KeyEvent::from(KeyCode::Tab));
        assert_eq!(app.active_panel, Panel::Flows); // no detail open
    }

    #[test]
    fn sort_column_cycles() {
        let mut app = App::new();
        assert_eq!(app.sort_column, SortColumn::LastSeen);
        app.handle_key(KeyEvent::from(KeyCode::Char('s')));
        assert_eq!(app.sort_column, SortColumn::Protocol);
    }

    #[test]
    fn sort_direction_toggles() {
        let mut app = App::new();
        assert!(!app.sort_ascending);
        app.handle_key(KeyEvent::from(KeyCode::Char('S')));
        assert!(app.sort_ascending);
    }
}
