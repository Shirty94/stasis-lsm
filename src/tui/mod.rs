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
    BpfWhitelist,
    Logs,
}

struct BpfWhitelistState {
    comm: String,
    value: u32,
}

struct ProcessUiState {
    comm: String,
    state: String,
    count: u32,
    last_update: Instant,
}

struct TuiState {
    processes: HashMap<u32, ProcessUiState>,
    bpf_whitelist: HashMap<u32, BpfWhitelistState>,
    bpf_blacklist: HashMap<u32, u8>,
    logs: VecDeque<(String, String)>, // (level, message)
    active_panel: ActivePanel,
}

impl TuiState {
    fn new() -> Self {
        Self {
            processes: HashMap::new(),
            bpf_whitelist: HashMap::new(),
            bpf_blacklist: HashMap::new(),
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
            ActivePanel::Processes => ActivePanel::BpfWhitelist,
            ActivePanel::BpfWhitelist => ActivePanel::Logs,
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

    /// Starts the main TUI event loop. Runs in a blocking context.
    pub fn run(mut self) -> Result<(), Box<dyn std::error::Error>> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let tick_rate = Duration::from_millis(250);
        let mut last_tick = Instant::now();

        loop {
            // draw the UI
            terminal.draw(|f| self.draw(f))?;

            // process incoming internal updates (drain the channel)
            while let Ok(event) = self.rx.try_recv() {
                self.handle_ui_event(event);
            }

            // process terminal user inputs (non-blocking poll)
            let timeout = tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or(Duration::from_secs(0));

            if event::poll(timeout)? {
                if let Event::Key(key) = event::read()? {
                    match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Tab => self.state.next_panel(),
                        _ => {}
                    }
                }
            }

            if last_tick.elapsed() >= tick_rate {
                last_tick = Instant::now();
            }
        }

        // restore terminal on exit
        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;

        Ok(())
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
                        comm,
                        state,
                        count,
                        last_update: Instant::now(),
                    },
                );
            }
            UiEvent::ProcessExited { pid } => {
                self.state.processes.remove(&pid);
            }
            UiEvent::BpfWhitelistAdd { pid, comm, value } => {
                self.state
                    .bpf_whitelist
                    .insert(pid, BpfWhitelistState { comm, value });
            }
            UiEvent::BpfWhitelistRemove { pid } => {
                self.state.bpf_whitelist.remove(&pid);
            }
            UiEvent::BpfWhitelistCounterUpdate { pid, value } => {
                if let Some(entry) = self.state.bpf_whitelist.get_mut(&pid) {
                    entry.value = value;
                }
            }
            UiEvent::Log { level, msg } => {
                self.state.push_log(level, msg);
            }
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

        // Helper to determine active border highlighting
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
                .title(" LIVE PROCESS TRACKING (Userspace) ")
                .borders(Borders::ALL)
                .border_style(get_border_style(ActivePanel::Processes)),
        );

        f.render_widget(process_table, top_chunks[0]);

        // right panel: kernel map status
        let bpf_rows: Vec<Row> = self
            .state
            .bpf_whitelist
            .iter()
            .map(|(&pid, entry)| {
                let status = if entry.value == 0xFFFFFFFF {
                    "Permanent Bypass".to_string()
                } else {
                    format!("Counter: {} / 10000", entry.value)
                };

                Row::new(vec![pid.to_string(), status, entry.comm.clone()])
                    .style(Style::default().fg(Color::Green))
            })
            .collect();

        let bpf_table = Table::new(
            bpf_rows,
            [
                Constraint::Percentage(15),
                Constraint::Percentage(40),
                Constraint::Percentage(45),
            ],
        )
        .header(
            Row::new(vec!["PID", "STATUS", "COMM"]).style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .block(
            Block::default()
                .title(" BPF KERNEL MAPS (Whitelist) ")
                .borders(Borders::ALL)
                .border_style(get_border_style(ActivePanel::BpfWhitelist)),
        );

        f.render_widget(bpf_table, top_chunks[1]);

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
