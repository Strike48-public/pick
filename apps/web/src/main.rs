//! Pentest Connector Web Application (Liveview)

use axum::Router;
use dioxus::prelude::*;
use dioxus_liveview::LiveviewRouter;
use std::net::SocketAddr;
use tokio::net::TcpListener;

use pentest_core::config::ShellMode;
use pentest_ui::{connector_app, mobile_css, theme_css, utils_css, ConnectorAppConfig};

/// Default port for the web UI when `PORT` is unset.
const DEFAULT_PORT: u16 = 3000;

/// How many consecutive ports to try before giving up. Keeps auto-increment
/// bounded so a misconfigured host can't spin forever.
const MAX_PORT_ATTEMPTS: u16 = 20;

/// Resolve the starting port from the `PORT` env var, falling back to
/// [`DEFAULT_PORT`]. A malformed value is rejected loudly rather than silently
/// ignored, so a typo'd `PORT` surfaces instead of masquerading as the default.
fn preferred_port() -> u16 {
    match std::env::var("PORT") {
        Ok(raw) => raw.trim().parse().unwrap_or_else(|_| {
            tracing::warn!(
                "PORT='{raw}' is not a valid port number; falling back to {DEFAULT_PORT}"
            );
            DEFAULT_PORT
        }),
        Err(_) => DEFAULT_PORT,
    }
}

/// Bind the first free port at or above `preferred`, scanning up to
/// [`MAX_PORT_ATTEMPTS`] ports. Returns the listener plus the port actually
/// bound so the caller can report the real URL. Only `AddrInUse` triggers a
/// retry; any other bind error is fatal and returned as-is.
async fn bind_with_fallback(preferred: u16) -> std::io::Result<(TcpListener, u16)> {
    for offset in 0..MAX_PORT_ATTEMPTS {
        // Stop rather than re-probe: near the u16 ceiling `preferred + offset`
        // would saturate and re-target the same top port, so a busy port high
        // in the range would spin uselessly. Skipping keeps every attempt a
        // distinct port.
        let Some(port) = preferred.checked_add(offset) else {
            break;
        };
        let addr = SocketAddr::from(([0, 0, 0, 0], port));
        match TcpListener::bind(&addr).await {
            Ok(listener) => {
                // Read the port back from the socket rather than trusting
                // `port`: with PORT=0 the OS assigns an ephemeral port, and the
                // caller must log the real one (not 0). Falls back to `port`
                // only if local_addr() somehow fails.
                let bound = listener.local_addr().map(|a| a.port()).unwrap_or(port);
                if offset > 0 {
                    tracing::warn!(
                        "Port {preferred} was in use; bound {bound} instead (set PORT to pin a specific port)"
                    );
                }
                return Ok((listener, bound));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                tracing::debug!("Port {port} in use, trying next");
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrInUse,
        format!(
            "no free port in {preferred}..{} after {MAX_PORT_ATTEMPTS} attempts",
            preferred.saturating_add(MAX_PORT_ATTEMPTS)
        ),
    ))
}

const WEB_CONFIG: ConnectorAppConfig = ConnectorAppConfig {
    platform_name: "Web (Liveview)",
    container_class: "mobile-app",
    shell_route_mode: ShellMode::Native,
    default_proot: true,
    start_liveview_server: false,
    inject_css: false,
    extra_init_messages: &["Tools execute on the server machine."],
    create_tools: pentest_tools::create_tool_registry,
    set_sandbox: Some(pentest_platform::set_use_sandbox),
};

#[tokio::main]
async fn main() {
    pentest_core::logging::init_logging("debug");

    tracing::info!("Starting Pentest Connector Web (Liveview)");

    let css = theme_css();
    let mcss = mobile_css();
    let ucss = utils_css();
    let full_css = format!("{css}{mcss}{ucss}");

    // Bind before building the app so a port collision (e.g. another local
    // Dioxus app already on 3000) fails fast with a clear message instead of
    // panicking or silently serving the wrong app.
    let (listener, port) = match bind_with_fallback(preferred_port()).await {
        Ok(bound) => bound,
        Err(e) => {
            tracing::error!("Could not bind a web UI port: {e}");
            eprintln!("error: could not bind a web UI port: {e}");
            std::process::exit(1);
        }
    };
    tracing::info!("Pick web UI available at http://localhost:{port}");

    let app = Router::new()
        .merge(pentest_ui::shell_ws::shell_routes(ShellMode::Native))
        .with_virtual_dom("/", move || {
            let css = full_css.clone();
            dioxus_core::VirtualDom::new_with_props(
                move || {
                    let css = css.clone();
                    use_effect(move || {
                        let css = css.clone();
                        document::eval(&format!(
                            r#"
                            var style = document.createElement('style');
                            style.textContent = `{}`;
                            document.head.appendChild(style);
                        "#,
                            css.replace('`', "\\`")
                        ));
                    });
                    connector_app(WEB_CONFIG)
                },
                (),
            )
        });

    axum::serve(listener, app.into_make_service())
        .await
        .expect("server error");
}
