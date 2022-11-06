use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use pnet::datalink::NetworkInterface;
use std::{
    error::Error,
    io,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use tui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, ListState},
    Frame, Terminal,
};

struct StatefulList<T> {
    state: ListState,
    items: Vec<T>,
}

impl<T> StatefulList<T> {
    fn with_items(items: Vec<T>) -> StatefulList<T> {
        StatefulList {
            state: ListState::default(),
            items,
        }
    }

    fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.items.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn unselect(&mut self) {
        self.state.select(None);
    }
}

/// This struct holds the current state of the app. In particular, it has the `items` field which is a wrapper
/// around `ListState`. Keeping track of the items state let us render the associated widget with its state
/// and have access to features such as natural scrolling.
///
/// Check the drawing logic for items on how to specify the highlighting style for selected items.
struct App {
    listening_seconds: u64,
    interfaces: StatefulList<NetworkInterface>,
    packets: StatefulList<String>,
}

impl App {
    fn new(interfaces: Vec<NetworkInterface>) -> App {
        App {
            listening_seconds: 5,
            interfaces: StatefulList::with_items(interfaces),
            packets: StatefulList::with_items(vec![]),
        }
    }

    pub fn add_message(&mut self, message: String) {
        self.packets.items.insert(0, message);
    }

    pub fn on_select(&mut self, index: usize) {
        let (transmitter, receiver) = mpsc::channel();
        let ni = self.interfaces.items[index].clone();
        thread::spawn(move || {
            if let Some(mut rx) = super::net::new_receiver(&ni) {
                loop {
                    if let Ok(packet) = rx.next() {
                        let packet_string = super::net::read_packet(&ni, packet);
                        _ = transmitter.send(packet_string);
                    }
                }
            }
        });
        let mut counter = 0;
        let started = Instant::now();
        while started.elapsed().as_secs() < self.listening_seconds {
            for received in receiver.recv_timeout(Duration::from_secs(1)) {
                counter += 1;
                self.packets.items.insert(0, received);
                if counter > 20 {
                    break;
                }
            }
        }
        self.add_message("[END] select again...".to_string());
    }
}

pub fn draw(items: Vec<NetworkInterface>) -> Result<(), Box<dyn Error>> {
    // setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // create app and run it
    let tick_rate = Duration::from_millis(250);
    let app = App::new(items);
    let res = run_app(&mut terminal, app, tick_rate);

    // restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err)
    }

    Ok(())
}

fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    mut app: App,
    tick_rate: Duration,
) -> io::Result<()> {
    let mut last_tick = Instant::now();
    loop {
        terminal.draw(|f| ui(f, &mut app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));
        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Esc => return Ok(()),
                    KeyCode::Enter => {
                        if let Some(index) = app.interfaces.state.selected() {
                            // TODO: Find a better solution for interactive processing.
                            app.add_message(
                                format!(
                                    "[START] monitoring {}. wait for {} seconds to get result...",
                                    app.interfaces.items[index].name, app.listening_seconds
                                )
                                .to_string(),
                            );
                            terminal.draw(|f| ui(f, &mut app))?;
                            app.on_select(index);
                        } else {
                            app.add_message("interface not selected!".to_string());
                        }
                    }
                    KeyCode::Left => app.interfaces.unselect(),
                    KeyCode::Down => {
                        app.interfaces.next();
                        terminal.draw(|f| ui(f, &mut app))?;
                    }
                    KeyCode::Up => {
                        app.interfaces.previous();
                        terminal.draw(|f| ui(f, &mut app))?;
                    }
                    _ => {}
                }
            }
        }
        if last_tick.elapsed() >= tick_rate {
            // app.on_tick();
            last_tick = Instant::now();
        }
    }
}

fn ui<B: Backend>(f: &mut Frame<B>, app: &mut App) {
    // Create two chunks with equal horizontal screen space
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(20), Constraint::Percentage(10)].as_ref())
        .split(f.size());

    let packet_items: Vec<ListItem> = app
        .packets
        .items
        .iter()
        .map(|packet| ListItem::new(packet.to_owned()))
        .collect();

    let packets =
        List::new(packet_items).block(Block::default().title("packets").borders(Borders::ALL));

    // Iterate through all elements in the `items` app and append some debug text to it.
    let interface_items: Vec<ListItem> = app
        .interfaces
        .items
        .iter()
        .map(|interface| {
            ListItem::new(format!(
                "{}: {}",
                interface.name,
                interface
                    .ips
                    .iter()
                    .map(|ip| ip.network().to_string())
                    .collect::<Vec<String>>()
                    .join(", ")
            ))
        })
        .collect();

    let interfaces = List::new(interface_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Interfaces: Enter to monitor"),
        )
        .highlight_style(
            Style::default()
                .bg(Color::LightGreen)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    // We can now render the item list
    f.render_stateful_widget(interfaces, chunks[0], &mut app.interfaces.state);
    f.render_stateful_widget(packets, chunks[1], &mut app.packets.state);
}
