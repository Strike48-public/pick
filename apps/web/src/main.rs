//! Pentest Connector Web Application (Liveview)

use axum::Router;
use dioxus::prelude::*;
use dioxus_liveview::LiveviewRouter;
use std::net::SocketAddr;

use pentest_core::config::ShellMode;
use pentest_ui::{connector_app, mobile_css, theme_css, utils_css, ConnectorAppConfig};

const WEB_CONFIG: ConnectorAppConfig = ConnectorAppConfig {
    platform_name: "Web (Liveview)",
    container_class: "mobile-app",
    shell_route_mode: ShellMode::Native,
    default_proot: false,
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

    let addr: SocketAddr = "0.0.0.0:3000"
        .parse()
        .expect("valid socket address literal");
    tracing::info!("Listening on http://{}", addr);

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

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind TCP listener");
    axum::serve(listener, app.into_make_service())
        .await
        .expect("server error");
}
