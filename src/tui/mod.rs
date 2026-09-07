use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, Row, Table},
};
use std::{
    collections::{HashMap, VecDeque},
    io,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

const MAX_LOGS: usize = 100;

#[derive(Debug, Clone)]
pub enum UiEvent {
    ProcessUpdated {
        pid: u32,
        comm: String,
        state: String,
        count: u32,
    },
    ProcessExited {
        pid: u32,
    },
    BpfWhitelistAdd {
        pid: u32,
        comm: String,
        value: u32,
    },
    BpfWhitelistRemove {
        pid: u32,
    },
    BpfWhitelistCounterUpdate {
        pid: u32,
        value: u32,
    },
    Log {
        level: String,
        msg: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivePanel {
    Processes,
    Alerts,
    Logs,
}

struct AlertUiState {
    pid: u32,
    comm: String,
    count: u32,
    active: bool,
}

struct ProcessUiState {
    comm: String,
    state: String,
    count: u32,
    last_update: Instant,
}

struct TuiState {
    processes: HashMap<u32, ProcessUiState>,
    alerts: HashMap<u32, AlertUiState>,
    logs: VecDeque<(String, String)>, // (level, message)
    active_panel: ActivePanel,
}

impl TuiState {
    fn new() -> Self {
        Self {
            processes: HashMap::new(),
            alerts: HashMap::new(),
            logs: VecDeque::with_capacity(MAX_LOGS),
            active_panel: ActivePanel::Processes,
        }
    }

    fn push_log(&mut self, level: String, msg: String) {
        if self.logs.len() >= MAX_LOGS {
            self.logs.pop_front();
        }
        self.logs.push_back((level, msg));
    }

    fn next_panel(&mut self) {
        self.active_panel = match self.active_panel {
            ActivePanel::Processes => ActivePanel::Alerts,
            ActivePanel::Alerts => ActivePanel::Logs,
            ActivePanel::Logs => ActivePanel::Processes,
        };
    }
}

pub struct Tui {
    rx: mpsc::Receiver<UiEvent>,
    state: TuiState,
}

impl Tui {
    pub fn new(rx: mpsc::Receiver<UiEvent>) -> Self {
        Self {
            rx,
            state: TuiState::new(),
        }
    }

    /// Prints a beautifully formatted colored line to stdout when TUI is inactive.
    fn print_cli_log(event: &UiEvent) {
        if let UiEvent::Log { level, msg } = event {
            let color_code = match level.as_str() {
                "ALERT" => "\x1b[1;31m", // Bold Red
                "WARN" => "\x1b[1;33m",  // Bold Yellow
                _ => "\x1b[1;36m",       // Bold Cyan
            };
            // \x1b[0m resets the text formatting
            println!("{}[{}]\x1b[0m {}", color_code, level, msg);
        }
    }

    /// Starts the main TUI event loop with a CLI fallback mode.
    pub fn run(mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut tui_active = true;

        loop {
            if tui_active {
                // initialize raw mode & alternate screen buffer
                enable_raw_mode()?;
                let mut stdout = io::stdout();
                execute!(stdout, EnterAlternateScreen)?;
                let backend = CrosstermBackend::new(stdout);
                let mut terminal = Terminal::new(backend)?;
                terminal.hide_cursor()?;

                let tick_rate = Duration::from_millis(1000);
                let mut last_tick = Instant::now();

                // active TUI loop
                loop {
                    terminal.draw(|f| self.draw(f))?;

                    // drain channel updates and update UI state
                    while let Ok(event) = self.rx.try_recv() {
                        self.handle_ui_event(event);
                    }

                    let timeout = tick_rate
                        .checked_sub(last_tick.elapsed())
                        .unwrap_or(Duration::from_secs(0));

                    if event::poll(timeout)? {
                        if let Event::Key(key) = event::read()? {
                            match key.code {
                                KeyCode::Char('q') => {
                                    tui_active = false;
                                    break;
                                }
                                KeyCode::Tab => self.state.next_panel(),
                                _ => {}
                            }
                        }
                    }

                    if last_tick.elapsed() >= tick_rate {
                        last_tick = Instant::now();
                    }
                }

                // cleanly restore terminal to normal shell state
                disable_raw_mode()?;
                execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
                terminal.show_cursor()?;

                println!("\n\x1b[1;33m[SYSTEM] TUI suspended. Monitoring continues in background.\x1b[0m");
                println!("\x1b[33mPress ENTER to restore TUI. Streaming live alerts below:\x1b[0m\n");
            } else {
                // check for keyboard input to resume TUI (blocks for up to 100ms)
                if event::poll(Duration::from_millis(100))? {
                    if let Event::Key(_) = event::read()? {
                        tui_active = true;
                        continue;
                    }
                }

                // stream events to stdout & update underlying TUI state
                while let Ok(event) = self.rx.try_recv() {
                    Self::print_cli_log(&event);
                    self.handle_ui_event(event);
                }
            }
        }
    }

    fn handle_ui_event(&mut self, event: UiEvent) {
        match event {
            UiEvent::ProcessUpdated {
                pid,
                comm,
                state,
                count,
            } => {
                self.state.processes.insert(
                    pid,
                    ProcessUiState {
                        comm: comm.clone(),
                        state: state.clone(),
                        count,
                        last_update: Instant::now(),
                    },
                );

                if state.contains("Alerted") {
                    self.state.alerts.insert(
                        pid,
                        AlertUiState {
                            pid,
                            comm,
                            count,
                            active: true,
                        },
                    );
                }
            }
            UiEvent::ProcessExited { pid } => {
                self.state.processes.remove(&pid);
                if let Some(alert) = self.state.alerts.get_mut(&pid) {
                    alert.active = false;
                }
            }
            UiEvent::Log { level, msg } => {
                self.state.push_log(level, msg);
            }
            UiEvent::BpfWhitelistAdd { .. }
            | UiEvent::BpfWhitelistRemove { .. }
            | UiEvent::BpfWhitelistCounterUpdate { .. } => {}
        }
    }

    fn draw(&self, f: &mut ratatui::Frame) {
        // vertical layout: top half for panels, bottom half for logs
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(f.area());

        // horizontal split for top panels
        let top_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(main_chunks[0]);

        // helper to determine active border highlighting
        let get_border_style = |panel: ActivePanel| {
            if self.state.active_panel == panel {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            }
        };

        // left panel: userspace processes
        let process_rows: Vec<Row> = self
            .state
            .processes
            .iter()
            .map(|(&pid, p)| {
                let state_style = match p.state.as_str() {
                    s if s.contains("Alerted") => {
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                    }
                    s if s.contains("White") => Style::default().fg(Color::Green),
                    s if s.contains("Monitor") => Style::default().fg(Color::Yellow),
                    _ => Style::default().fg(Color::DarkGray),
                };

                Row::new(vec![
                    pid.to_string(),
                    p.comm.clone(),
                    p.state.clone(),
                    p.count.to_string(),
                ])
                .style(state_style)
            })
            .collect();

        let process_table = Table::new(
            process_rows,
            [
                Constraint::Percentage(20),
                Constraint::Percentage(30),
                Constraint::Percentage(35),
                Constraint::Percentage(15),
            ],
        )
        .header(
            Row::new(vec!["PID", "COMM", "STATE", "OPENS"]).style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .block(
            Block::default()
                .title(" LIVE PROCESS TRACKING ")
                .borders(Borders::ALL)
                .border_style(get_border_style(ActivePanel::Processes)),
        );

        f.render_widget(process_table, top_chunks[0]);

        // right panel: threat alerts
        let alert_rows: Vec<Row> = self
            .state
            .alerts
            .iter()
            .map(|(&pid, alert)| {
                let (status_str, style) = if alert.active {
                    (
                        "ACTIVE THREAT",
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    )
                } else {
                    ("TERMINATED", Style::default().fg(Color::DarkGray))
                };

                Row::new(vec![
                    pid.to_string(),
                    alert.comm.clone(),
                    alert.count.to_string(),
                    status_str.to_string(),
                ])
                .style(style)
            })
            .collect();

        let alert_table = Table::new(
            alert_rows,
            [
                Constraint::Percentage(15),
                Constraint::Percentage(40),
                Constraint::Percentage(20),
                Constraint::Percentage(25),
            ],
        )
        .header(
            Row::new(vec!["PID", "COMM", "OPENS", "STATUS"])
                .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        )
        .block(
            Block::default()
                .title(" SUSPICIOUS & BLOCKED PROCESSES ")
                .borders(Borders::ALL)
                .border_style(get_border_style(ActivePanel::Alerts)),
        );

        f.render_widget(alert_table, top_chunks[1]);

        // bottom panel: system activity logs
        let logs: Vec<ListItem> = self
            .state
            .logs
            .iter()
            .map(|(level, msg)| {
                let color = match level.as_str() {
                    "ALERT" => Color::Red,
                    "WARN" => Color::Yellow,
                    _ => Color::LightBlue,
                };
                ListItem::new(format!("[{}] {}", level, msg)).style(Style::default().fg(color))
            })
            .collect();

        let log_list = List::new(logs).block(
            Block::default()
                .title(" SYSTEM ACTIVITY LOGS (Press 'q' to exit, 'Tab' to switch panels) ")
                .borders(Borders::ALL)
                .border_style(get_border_style(ActivePanel::Logs)),
        );

        f.render_widget(log_list, main_chunks[1]);
    }
}
