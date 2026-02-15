use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use crate::models::{Protocol, Severity};

use super::app::{App, DetailView, Panel};
use super::state::LiveCounters;

pub fn render(frame: &mut Frame, app: &mut App, counters: &LiveCounters) {
    let [header_area, body_area, footer_area] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    render_header(frame, header_area, counters);
    render_body(frame, body_area, app);
    render_footer(frame, footer_area, app);
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

fn render_header(frame: &mut Frame, area: Rect, counters: &LiveCounters) {
    let uptime = counters.uptime();
    let hours = uptime.as_secs() / 3600;
    let mins = (uptime.as_secs() % 3600) / 60;
    let secs = uptime.as_secs() % 60;

    let line1 = Line::from(vec![
        Span::styled(
            "  VIGIL  ",
            Style::default().fg(Color::Black).bg(Color::Cyan).bold(),
        ),
        Span::raw("  "),
        Span::styled(
            format!("Uptime: {hours:02}:{mins:02}:{secs:02}"),
            Style::default().fg(Color::White),
        ),
        Span::raw("  │  "),
        Span::styled(
            format!("Pkts: {}", format_count(counters.packets())),
            Style::default().fg(Color::Green),
        ),
        Span::raw("  │  "),
        Span::styled(
            format!("Flows: {}", format_count(counters.flows())),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw("  │  "),
        Span::styled(
            format!("Alerts: {}", counters.alerts()),
            Style::default().fg(Color::Red),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(Color::DarkGray));

    let header = Paragraph::new(vec![Line::raw(""), line1]).block(block);
    frame.render_widget(header, area);
}

// ---------------------------------------------------------------------------
// Body
// ---------------------------------------------------------------------------

fn render_body(frame: &mut Frame, area: Rect, app: &mut App) {
    let has_detail = app.detail_view.is_some();

    if has_detail {
        let [left, right] = Layout::horizontal([
            Constraint::Percentage(60),
            Constraint::Percentage(40),
        ])
        .areas(area);

        render_left_panels(frame, left, app);
        render_detail(frame, right, app);
    } else {
        render_left_panels(frame, area, app);
    }
}

fn render_left_panels(frame: &mut Frame, area: Rect, app: &mut App) {
    let [flows_area, alerts_area] = Layout::vertical([
        Constraint::Percentage(65),
        Constraint::Percentage(35),
    ])
    .areas(area);

    render_flows_table(frame, flows_area, app);
    render_alerts_table(frame, alerts_area, app);
}

fn render_flows_table(frame: &mut Frame, area: Rect, app: &mut App) {
    let active = app.active_panel == Panel::Flows;
    let border_color = if active { Color::Cyan } else { Color::DarkGray };
    let sort_indicator = format!(
        " [sort: {} {}] ",
        app.sort_column,
        if app.sort_ascending { "▲" } else { "▼" }
    );

    let block = Block::default()
        .title(" Flows ")
        .title_bottom(Line::from(sort_indicator).right_aligned())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let header = Row::new(["Proto", "Source", "Destination", "Pkts", "Bytes", "Last Seen"])
        .style(Style::default().bold().fg(Color::White));

    // Sort flows before building rows
    app.sorted_flows();
    let rows: Vec<Row> = app
        .cached_flows
        .iter()
        .map(|f| {
            let proto_color = match f.protocol {
                Protocol::Tcp => Color::Green,
                Protocol::Udp => Color::Yellow,
                Protocol::Icmp => Color::Magenta,
                Protocol::Other(_) => Color::DarkGray,
            };
            Row::new([
                Cell::from(format!("{:?}", f.protocol))
                    .style(Style::default().fg(proto_color)),
                Cell::from(format!("{}:{}", f.src_ip, f.src_port)),
                Cell::from(format!("{}:{}", f.dst_ip, f.dst_port)),
                Cell::from(format_count(f.packet_count)),
                Cell::from(format_bytes(f.byte_count)),
                Cell::from(f.last_seen_at.format("%H:%M:%S").to_string()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Length(8),
            Constraint::Length(9),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(block)
    .row_highlight_style(
        Style::default()
            .bg(if active { Color::DarkGray } else { Color::Black })
            .add_modifier(Modifier::BOLD),
    );

    frame.render_stateful_widget(table, area, &mut app.flows_state);
}

fn render_alerts_table(frame: &mut Frame, area: Rect, app: &mut App) {
    let active = app.active_panel == Panel::Alerts;
    let border_color = if active { Color::Cyan } else { Color::DarkGray };

    let block = Block::default()
        .title(" Alerts ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let header = Row::new(["Sev", "Kind", "Title", "Time"])
        .style(Style::default().bold().fg(Color::White));

    let rows: Vec<Row> = app
        .cached_alerts
        .iter()
        .map(|a| {
            let (sev_str, sev_color) = severity_display(a.severity);
            Row::new([
                Cell::from(sev_str).style(Style::default().fg(sev_color)),
                Cell::from(format!("{:?}", a.kind)),
                Cell::from(a.title.clone()),
                Cell::from(a.created_at.format("%H:%M:%S").to_string()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(18),
            Constraint::Fill(1),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(block)
    .row_highlight_style(
        Style::default()
            .bg(if active { Color::DarkGray } else { Color::Black })
            .add_modifier(Modifier::BOLD),
    );

    frame.render_stateful_widget(table, area, &mut app.alerts_state);
}

fn render_detail(frame: &mut Frame, area: Rect, app: &App) {
    let active = app.active_panel == Panel::Detail;
    let border_color = if active { Color::Cyan } else { Color::DarkGray };

    let block = Block::default()
        .title(" Detail ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let content = match app.detail_view {
        Some(DetailView::FlowDetail(i)) => {
            if let Some(f) = app.cached_flows.get(i) {
                vec![
                    Line::from(vec![
                        Span::styled("Flow ID: ", Style::default().bold()),
                        Span::raw(f.flow_id.to_string()),
                    ]),
                    Line::raw(""),
                    detail_line("Protocol", &format!("{:?}", f.protocol)),
                    detail_line("Source", &format!("{}:{}", f.src_ip, f.src_port)),
                    detail_line("Dest", &format!("{}:{}", f.dst_ip, f.dst_port)),
                    Line::raw(""),
                    detail_line("Packets", &format_count(f.packet_count)),
                    detail_line("Bytes", &format_bytes(f.byte_count)),
                    detail_line("Avg Pkt Len", &format!("{:.1}", f.avg_packet_len)),
                    detail_line("Avg IAT", &format!("{:.1} ms", f.avg_inter_arrival_ms)),
                    Line::raw(""),
                    detail_line("SYN count", &f.syn_count.to_string()),
                    detail_line("FIN count", &f.fin_count.to_string()),
                    Line::raw(""),
                    detail_line(
                        "Started",
                        &f.started_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                    ),
                    detail_line(
                        "Last seen",
                        &f.last_seen_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                    ),
                ]
            } else {
                vec![Line::raw("Flow not found")]
            }
        }
        Some(DetailView::AlertDetail(i)) => {
            if let Some(a) = app.cached_alerts.get(i) {
                let (sev_str, sev_color) = severity_display(a.severity);
                let mut lines = vec![
                    Line::from(vec![
                        Span::styled("Alert ID: ", Style::default().bold()),
                        Span::raw(a.alert_id.to_string()),
                    ]),
                    Line::raw(""),
                    Line::from(vec![
                        Span::styled("Severity: ", Style::default().bold()),
                        Span::styled(sev_str, Style::default().fg(sev_color).bold()),
                    ]),
                    detail_line("Kind", &format!("{:?}", a.kind)),
                    detail_line("Title", &a.title),
                    Line::raw(""),
                    detail_line("Flow ID", &a.flow_id.to_string()),
                    detail_line(
                        "Time",
                        &a.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                    ),
                    Line::raw(""),
                    Line::styled("Detail:", Style::default().bold()),
                    Line::raw(a.detail.clone()),
                ];
                if let Some(ref summary) = a.llm_summary {
                    lines.push(Line::raw(""));
                    lines.push(Line::styled(
                        "LLM Summary:",
                        Style::default().bold().fg(Color::Cyan),
                    ));
                    lines.push(Line::raw(summary.clone()));
                }
                lines
            } else {
                vec![Line::raw("Alert not found")]
            }
        }
        None => vec![Line::raw("Press Enter on a flow or alert to view details")],
    };

    let detail = Paragraph::new(content)
        .block(block)
        .wrap(Wrap { trim: true });
    frame.render_widget(detail, area);
}

// ---------------------------------------------------------------------------
// Footer
// ---------------------------------------------------------------------------

fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
    let hints = vec![
        Span::styled(" q", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Quit  "),
        Span::styled("Tab", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Panel  "),
        Span::styled("j/k", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Nav  "),
        Span::styled("Enter", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Detail  "),
        Span::styled("Esc", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Close  "),
        Span::styled("s", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Sort  "),
        Span::styled("S", Style::default().fg(Color::Yellow).bold()),
        Span::raw(":Dir  "),
        Span::raw("  "),
        Span::styled(
            format!("[{}]", app.active_panel_name()),
            Style::default().fg(Color::Cyan),
        ),
    ];

    let footer = Paragraph::new(Line::from(hints));
    frame.render_widget(footer, area);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn severity_display(sev: Severity) -> (&'static str, Color) {
    match sev {
        Severity::Critical => ("CRIT", Color::Red),
        Severity::High => ("HIGH", Color::LightRed),
        Severity::Medium => ("MED", Color::Yellow),
        Severity::Low => ("LOW", Color::Cyan),
    }
}

fn detail_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label}: "), Style::default().bold()),
        Span::raw(value.to_string()),
    ])
}

fn format_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn format_bytes(n: u64) -> String {
    if n >= 1_073_741_824 {
        format!("{:.1} GB", n as f64 / 1_073_741_824.0)
    } else if n >= 1_048_576 {
        format!("{:.1} MB", n as f64 / 1_048_576.0)
    } else if n >= 1_024 {
        format!("{:.1} KB", n as f64 / 1_024.0)
    } else {
        format!("{n} B")
    }
}

impl App {
    pub fn active_panel_name(&self) -> &'static str {
        match self.active_panel {
            Panel::Flows => "Flows",
            Panel::Alerts => "Alerts",
            Panel::Detail => "Detail",
        }
    }
}
