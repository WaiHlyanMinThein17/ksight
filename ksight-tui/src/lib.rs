use std::collections::VecDeque;

use ksight_common::HIST_BUCKETS;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::Line,
    widgets::{Bar, BarChart, BarGroup, Block, Borders, Paragraph},
};

pub const MAX_EVENTS: usize = 200;

pub struct EventRecord {
    pub line: String,
}

pub struct AppState {
    pub events: VecDeque<EventRecord>,
    pub histogram: [u64; HIST_BUCKETS],
    pub filter_label: String,
    pub event_count: u64,
}

impl AppState {
    pub fn new(filter_label: String) -> Self {
        Self {
            events: VecDeque::with_capacity(MAX_EVENTS),
            histogram: [0; HIST_BUCKETS],
            filter_label,
            event_count: 0,
        }
    }

    pub fn push_event(&mut self, line: String) {
        if self.events.len() == MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(EventRecord { line });
        self.event_count += 1;
    }
}

pub fn render(frame: &mut Frame, state: &AppState) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(frame.area());

    let header = format!(
        " ksight   filter: {}   events: {}   q: quit",
        state.filter_label, state.event_count
    );
    frame.render_widget(
        Paragraph::new(header).style(Style::default().fg(Color::Black).bg(Color::Cyan)),
        outer[0],
    );

    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(outer[1]);

    let lines: Vec<Line> = state
        .events
        .iter()
        .rev()
        .map(|e| Line::from(e.line.as_str()))
        .collect();
    frame.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("Events")),
        panes[0],
    );

    render_histogram(frame, state, panes[1]);
}

fn render_histogram(frame: &mut Frame, state: &AppState, area: ratatui::layout::Rect) {
    let bars: Vec<Bar> = state
        .histogram
        .iter()
        .enumerate()
        .filter(|&(_, &c)| c > 0)
        .map(|(b, &count)| {
            let low_us = (1u64 << b) / 1000;
            Bar::default()
                .value(count)
                .label(Line::from(format!("{}us", low_us)))
        })
        .collect();

    let chart = BarChart::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("I/O latency (us)"),
        )
        .data(BarGroup::default().bars(&bars))
        .bar_width(6)
        .bar_gap(1)
        .bar_style(Style::default().fg(Color::Green));

    frame.render_widget(chart, area);
}
