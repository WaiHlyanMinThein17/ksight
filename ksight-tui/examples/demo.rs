use std::time::Duration;

use crossterm::event::{self, Event, KeyCode};
use ksight_tui::{AppState, render};

fn main() -> std::io::Result<()> {
    let mut state = AppState::new("comm=cat".to_string());
    for i in 0..10 {
        state.push_event(format!(
            "OPEN  pid={:<6} comm=cat   /etc/file{}",
            1000 + i,
            i
        ));
    }
    state.histogram[16] = 11;
    state.histogram[17] = 43;
    state.histogram[18] = 92;
    state.histogram[19] = 181;
    state.histogram[20] = 30;
    state.histogram[21] = 18;

    let mut terminal = ratatui::init();
    loop {
        terminal.draw(|f| render(f, &state))?;
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(k) = event::read()? {
                if k.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
    }
    ratatui::restore();
    Ok(())
}
