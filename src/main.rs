//! tresor binary — tokio/crossterm terminal event loop.

use std::io::stdout;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyCode, KeyEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use futures::StreamExt as _;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use secrecy::ExposeSecret as _;
use tokio::sync::mpsc;
use tokio::time;
use tresor::app::{App, AppState};
use tresor::config::Config;
use tresor::editor::{CommandTextEditor, EditBuffer, EditOutcome, EditorError, TextEditor};
use tresor::path::SecretPath;
use tresor::profiles::{self, ConnectRequest, Profiles};
use tresor::store::Msg;
use tresor::theme::Theme;
use tresor::vault::{VaultApi as _, VaultClient};

type ReconnectResult = Result<(Config, Arc<VaultClient>, Option<String>), String>;

#[tokio::main]
#[allow(
    clippy::too_many_lines,
    reason = "single terminal event-loop entry point; splitting obscures the select! flow"
)]
async fn main() -> Result<()> {
    // Default to our crate's own events only; third-party crates (rustify,
    // vaultrs, hyper, rustls) log noisy errors over the `log` bridge that would
    // smear into the alternate screen. RUST_LOG overrides.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("tresor=warn,off"));
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .init();

    match std::env::args().nth(1).as_deref() {
        Some("--check") => {
            let check_config = check_config_from_env_or_profile().await?;
            return run_check(check_config).await;
        }
        Some("--version" | "-V") => {
            print_version();
            return Ok(());
        }
        Some("--help" | "-h") => {
            print_help();
            return Ok(());
        }
        _ => {}
    }

    let (mut app, mut msg_rx) = build_app().await?;
    let (connect_tx, mut connect_rx) = mpsc::unbounded_channel::<ReconnectResult>();

    install_panic_hook();
    let mut terminal = init_terminal()?;
    let mut events = EventStream::new();
    let mut tick = time::interval(Duration::from_secs(1));
    let mut dirty = true;
    let mut quit = false;
    let editor = CommandTextEditor::default_editor().ok();

    while !quit {
        if dirty {
            terminal
                .draw(|frame| app.draw(frame, frame.area()))
                .context("failed to draw terminal")?;
            dirty = false;
        }

        tokio::select! {
            maybe_event = events.next() => {
                if let Some(event) = maybe_event {
                    let event = event.context("failed to read terminal event")?;
                    if let Event::Key(key) = event {
                        if key.kind == KeyEventKind::Press {
                            if matches!(app.state, AppState::ConfigInput) && key.code == KeyCode::Enter {
                                let config = app.modal_config();
                                match VaultClient::connect(&config.addr, config.token.expose_secret()) {
                                    Ok(vault) => app.connect_config(config, Arc::new(vault)),
                                    Err(err) => app.set_modal_error(err.message()),
                                }
                            } else {
                                quit = app.handle_input(key);
                                if let Some(request) = app.take_pending_connect() {
                                    spawn_connect_request(request, connect_tx.clone());
                                }
                                drain_editor_requests(
                                    &mut app,
                                    &mut terminal,
                                    &mut events,
                                    editor.as_ref(),
                                );
                            }
                            dirty = true;
                        }
                    }
                } else {
                    quit = true;
                }
            }
            maybe_msg = msg_rx.recv() => {
                if let Some(msg) = maybe_msg {
                    app.apply(msg);
                    drain_editor_requests(
                        &mut app,
                        &mut terminal,
                        &mut events,
                        editor.as_ref(),
                    );
                    dirty = true;
                }
            }
            maybe_connect = connect_rx.recv() => {
                if let Some(result) = maybe_connect {
                    apply_connect_result(&mut app, result);
                    dirty = true;
                }
            }
            _instant = tick.tick() => {
                app.expire_status();
                dirty = true;
            }
        }
    }

    restore_terminal();
    Ok(())
}

#[allow(
    clippy::print_stdout,
    reason = "CLI surface; stdout is the report channel"
)]
fn print_version() {
    println!("tresor {}", env!("CARGO_PKG_VERSION"));
}

#[allow(
    clippy::print_stdout,
    reason = "CLI surface; stdout is the report channel"
)]
fn print_help() {
    println!(
        "tresor {} — a k9s-style TUI for HashiCorp Vault and OpenBao

USAGE:
  tresor             run the TUI
  tresor --check     connectivity/API diagnostic (health, token, engines, KV2 list)
  tresor --version   print the version
  tresor --help      print this help

CONFIGURATION (first match wins):
  BAO_ADDR / VAULT_ADDR              Vault or OpenBao address
  BAO_TOKEN / VAULT_TOKEN            authentication token
  BAO_TOKEN_PATH / VAULT_TOKEN_PATH  CLI token store override
  ~/.vault-token                     written by `vault login` / `bao login`
  ~/.config/tresor/config.toml       named connection profiles (`:ctx`); $TRESOR_CONFIG overrides",
        env!("CARGO_PKG_VERSION")
    );
}

async fn build_app() -> Result<(App<VaultClient>, mpsc::UnboundedReceiver<Msg>)> {
    let profiles = profiles::load_profiles().unwrap_or_default();
    let env_config = Config::from_env();
    let (startup_choice, connected, profile_name) =
        resolve_startup_choice(env_config, &profiles).await;

    let startup_config = startup_choice
        .clone()
        .unwrap_or_else(|| Config::new("http://127.0.0.1:8200", ""));
    let vault = Arc::new(
        VaultClient::connect(&startup_config.addr, startup_config.token.expose_secret())
            .context("failed to initialize Vault client")?,
    );
    let theme = Theme::load_sofka_or_default();
    let (mut app, msg_rx) = match startup_choice {
        Some(config) if connected => App::new_with_theme(config, vault, theme),
        _ => App::config_input_with_theme(vault, theme),
    };
    app = app.with_profiles(profiles);
    if connected {
        app.set_current_profile(profile_name);
    }
    if !matches!(app.state, AppState::ConfigInput) {
        app.spawn_initial_loads();
    }
    Ok((app, msg_rx))
}

async fn check_config_from_env_or_profile() -> Result<Config> {
    if let Some(config) = Config::from_env() {
        return Ok(config);
    }
    let profiles = profiles::load_profiles().unwrap_or_default();
    let Some(profile) = profiles.current() else {
        return Err(anyhow::anyhow!(
            "no configuration: set BAO_ADDR (or VAULT_ADDR) and provide a token \
             (BAO_TOKEN/VAULT_TOKEN env or the ~/.vault-token written by `bao login`)"
        ));
    };
    profile
        .to_request()
        .resolve_config()
        .await
        .context("failed to resolve current profile")
}

async fn resolve_startup_choice(
    env_config: Option<Config>,
    profiles: &Profiles,
) -> (Option<Config>, bool, Option<String>) {
    if let Some(config) = env_config {
        return (Some(config), true, None);
    }
    let Some(profile) = profiles.current() else {
        return (None, false, None);
    };
    match profile.to_request().resolve_config().await {
        Ok(config) => (Some(config), true, Some(profile.name.clone())),
        Err(err) => {
            tracing::warn!(
                %err,
                profile = %profile.name,
                "failed to resolve current profile, falling back to config modal"
            );
            (None, false, None)
        }
    }
}

fn spawn_connect_request(request: ConnectRequest, tx: mpsc::UnboundedSender<ReconnectResult>) {
    tokio::spawn(async move {
        let name = request.profile_name.clone();
        let result = match request.resolve_config().await {
            Ok(config) => match VaultClient::connect(&config.addr, config.token.expose_secret()) {
                Ok(vault) => Ok((config, Arc::new(vault), name)),
                Err(err) => Err(err.message()),
            },
            Err(err) => Err(err.to_string()),
        };
        let _send_result = tx.send(result);
    });
}

fn apply_connect_result(app: &mut App<VaultClient>, result: ReconnectResult) {
    match result {
        Ok((config, vault, name)) => {
            app.connect_config(config, vault);
            app.set_current_profile(name);
        }
        Err(message) => app.report_error(message),
    }
}

fn restore_terminal() {
    if let Err(err) = disable_raw_mode() {
        tracing::warn!(%err, "failed to disable raw mode");
    }
    let mut out = stdout();
    if let Err(err) = execute!(out, LeaveAlternateScreen, DisableMouseCapture) {
        tracing::warn!(%err, "failed to restore terminal screen");
    }
}

fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        default_hook(info);
    }));
}

fn init_terminal() -> Result<Terminal<CrosstermBackend<std::io::Stdout>>> {
    enable_raw_mode().context("failed to enable raw mode")?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen, EnableMouseCapture)
        .context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(out);
    Terminal::new(backend).context("failed to create terminal")
}

struct TerminalSuspendGuard<'a> {
    terminal: &'a mut Terminal<CrosstermBackend<std::io::Stdout>>,
}

impl<'a> TerminalSuspendGuard<'a> {
    const fn new(terminal: &'a mut Terminal<CrosstermBackend<std::io::Stdout>>) -> Self {
        Self { terminal }
    }
}

impl Drop for TerminalSuspendGuard<'_> {
    fn drop(&mut self) {
        if let Err(err) = enable_raw_mode() {
            tracing::warn!(%err, "failed to re-enable raw mode after editor handoff");
        }
        if let Err(err) = execute!(
            self.terminal.backend_mut(),
            EnterAlternateScreen,
            EnableMouseCapture
        ) {
            tracing::warn!(%err, "failed to restore alternate screen after editor handoff");
        }
        if let Err(err) = self.terminal.clear() {
            tracing::warn!(%err, "failed to clear screen after editor handoff");
        }
    }
}

fn run_editor_handoff(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    editor: Option<&CommandTextEditor>,
    buffer: &EditBuffer,
) -> Result<EditOutcome, EditorError> {
    // Arm the restore guard before the first terminal mutation so `Drop` restores
    // the terminal even if a suspend step fails partway.
    let guard = TerminalSuspendGuard::new(terminal);
    guard
        .terminal
        .show_cursor()
        .map_err(|err| EditorError::Command(err.to_string()))?;
    execute!(
        guard.terminal.backend_mut(),
        DisableMouseCapture,
        LeaveAlternateScreen
    )
    .map_err(|err| EditorError::Command(err.to_string()))?;
    disable_raw_mode().map_err(|err| EditorError::Command(err.to_string()))?;

    let Some(editor) = editor else {
        return Err(EditorError::MissingEditor);
    };
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| editor.edit(buffer))).ok();
    drop(guard);
    result.unwrap_or(Err(EditorError::Panicked))
}

fn drain_editor_requests(
    app: &mut App<VaultClient>,
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    events: &mut EventStream,
    editor: Option<&CommandTextEditor>,
) {
    while let Some(request) = app.take_editor_request() {
        let result = run_editor_handoff(terminal, editor, &request.buffer);
        app.complete_editor_request(request, result);
        *events = EventStream::new();
    }
}

/// Prints a plain-text connectivity/API diagnostic (health, token, engines,
/// per-engine KV2 list) and fails fast on the first error — the screenshot-free
/// retest and debugging path (`tresor --check`).
#[allow(
    clippy::print_stdout,
    reason = "diagnostic CLI surface; stdout is the report channel"
)]
async fn run_check(config: Config) -> Result<()> {
    let vault = VaultClient::connect(&config.addr, config.token.expose_secret())
        .context("failed to initialize Vault client")?;
    println!("addr: {}", config.addr);

    match vault.sys_health().await {
        Ok(health) => println!(
            "health: OK (sealed: {}, vault: {})",
            health.sealed, health.version
        ),
        Err(err) => return check_error("health", &err),
    }

    match vault.read_token_info().await {
        Ok(info) => {
            let eternal = if info.is_eternal() { ", eternal" } else { "" };
            println!(
                "token: OK (policies: {}{})",
                info.policies.join(", "),
                eternal
            );
        }
        Err(err) => return check_error("token", &err),
    }

    let engines = match vault.read_secret_engines().await {
        Ok(engines) => {
            println!("engines: {} mounts", engines.len());
            engines
        }
        Err(err) => return check_error("engines", &err),
    };

    for engine in &engines {
        // Only KV2 mounts can be browsed; report the rest instead of probing.
        if !engine.supports_browsing() {
            println!(
                "  {} ({}): not browsable (only KV2 engines are)",
                engine.name,
                engine.type_label()
            );
            continue;
        }
        match vault
            .list_kv_secrets(&engine.name, &SecretPath::root())
            .await
        {
            Ok(entries) => println!(
                "  list {} ({}): OK ({} keys)",
                engine.name,
                engine.type_label(),
                entries.len()
            ),
            Err(tresor::vault::VaultError::Api { status: 404, .. }) => {
                println!("  list {}: empty or unavailable (skipped)", engine.name);
            }
            Err(err) => return check_error(&format!("list {}", engine.name), &err),
        }
    }
    Ok(())
}

fn check_error(step: &str, err: &tresor::vault::VaultError) -> Result<()> {
    Err(anyhow::anyhow!("{step}: FAILED — {}", err.message()))
}
