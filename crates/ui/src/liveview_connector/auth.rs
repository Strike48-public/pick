//! OTT approval flow, credentials handling, and token refresh logic.

use pentest_core::terminal::TerminalLine;
use std::sync::atomic::Ordering;
use strike48_connector::OttProvider;
use strike48_proto::proto::CredentialsIssued;

use super::{ConnectorEvent, LiveViewConnector};
use crate::components::ConnectingStep;

impl LiveViewConnector {
    /// Fallback: fetch a Matrix chat token via browser-based OAuth login.
    pub(crate) async fn try_fetch_matrix_token_fallback(&mut self) {
        let api_url = self.derive_matrix_api_url();
        tracing::info!(
            "[FetchTokenFallback] Trying browser-based OAuth login ({})",
            api_url
        );
        self.send_event(ConnectorEvent::Log(TerminalLine::info(
            "Trying browser login for chat token...",
        )));

        match pentest_core::matrix::fetch_matrix_token_browser(&api_url).await {
            Ok(token) => {
                tracing::info!(
                    "[FetchTokenFallback] Got token via browser OAuth (len={})",
                    token.len(),
                );
                crate::liveview_server::set_matrix_credentials(&api_url, &token);
                crate::session::set_auth_token(&token);
                self.send_event(ConnectorEvent::Log(TerminalLine::success(
                    "Chat token obtained via browser login",
                )));
                self.send_event(ConnectorEvent::MatrixTokenObtained {
                    auth_token: token,
                    api_url: api_url.clone(),
                });
            }
            Err(e) => {
                tracing::warn!("[FetchTokenFallback] browser OAuth failed: {}", e,);
                self.send_event(ConnectorEvent::Log(TerminalLine::info(format!(
                    "Chat token fetch failed ({}), waiting for approval...",
                    e
                ))));
                self.send_event(ConnectorEvent::StepChanged(
                    ConnectingStep::WaitingForApproval,
                ));
            }
        }
    }

    /// Handle post-registration auth: wait for admin approval or browser fallback.
    ///
    /// Called from the message loop when registration succeeds but no JWT is present.
    /// Saved credentials are now loaded *before* the connection loop (in connect_and_run)
    /// to avoid disrupting an already-successful registration with a reconnect cycle.
    pub(crate) async fn handle_post_registration_auth(&mut self) {
        if std::env::var("STRIKEHUB_SOCKET").is_ok() {
            tracing::info!("[RegisterResponse] StrikeHub mode: waiting for admin approval");
            self.send_event(ConnectorEvent::Log(TerminalLine::info(
                "Waiting for admin approval in Studio…",
            )));
            self.send_event(ConnectorEvent::StepChanged(
                ConnectingStep::WaitingForApproval,
            ));
        } else {
            tracing::info!("[RegisterResponse] No JWT, trying browser login fallback");
            self.try_fetch_matrix_token_fallback().await;
        }
    }

    /// Handle credentials issued (post-approval OTT exchange)
    pub(crate) async fn handle_credentials_issued(&mut self, creds: CredentialsIssued) {
        self.send_event(ConnectorEvent::Log(TerminalLine::info(
            "Processing approval credentials...",
        )));

        if creds.ott.is_empty() {
            tracing::error!("No OTT in credentials_issued message");
            self.send_event(ConnectorEvent::Log(TerminalLine::error(
                "No OTT in credentials message",
            )));
            return;
        }

        // Prefer local override (MATRIX_API_URL env var) over server-provided URL
        // so in-cluster deployments can route OTT registration to the internal service.
        let derived = self.derive_matrix_api_url();
        let ott_api_url = if derived.is_empty() {
            &creds.matrix_api_url
        } else {
            &derived
        };

        if ott_api_url.is_empty() {
            tracing::error!("No api_url in credentials_issued message");
            self.send_event(ConnectorEvent::Log(TerminalLine::error(
                "No API URL in credentials message",
            )));
            return;
        }

        // Use connector_name from config (controls gateway identity in Matrix)
        let connector_type = self.config.connector_name.clone();

        let mut ott_provider = OttProvider::new(
            Some(connector_type.clone()),
            Some(self.config.instance_id.clone()),
        );

        // Register public key with OTT
        match ott_provider
            .register_public_key_with_ott_data(
                &creds.ott,
                ott_api_url,
                &creds.register_url,
                &connector_type,
                Some(&self.config.instance_id),
            )
            .await
        {
            Ok(response) => {
                tracing::info!(
                    "Registered public key with OTT. Client ID: {}",
                    response.client_id
                );
                self.send_event(ConnectorEvent::Log(TerminalLine::success(format!(
                    "Key registered: {}",
                    response.client_id
                ))));

                // Get JWT using private_key_jwt
                match ott_provider.get_token().await {
                    Ok(jwt_token) => {
                        tracing::info!("Obtained JWT, will reconnect with JWT authentication");
                        self.send_event(ConnectorEvent::Log(TerminalLine::success(
                            "JWT obtained, reconnecting...",
                        )));

                        // Update config with new JWT
                        self.config.auth_token = jwt_token.clone();

                        // Notify main app to save credentials
                        self.send_event(ConnectorEvent::CredentialsUpdated {
                            auth_token: jwt_token,
                            api_url: self.derive_matrix_api_url(),
                        });

                        // Store OTT provider for token refresh
                        *self.ott_provider.write().await = Some(ott_provider);

                        // Set flag to trigger reconnection
                        self.reconnect_with_jwt.store(true, Ordering::SeqCst);
                    }
                    Err(e) => {
                        tracing::error!("Failed to get JWT: {}", e);
                        self.send_event(ConnectorEvent::Log(TerminalLine::error(format!(
                            "JWT exchange failed: {}",
                            e
                        ))));
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to register public key with OTT: {}", e);
                self.send_event(ConnectorEvent::Log(TerminalLine::error(format!(
                    "OTT registration failed: {}",
                    e
                ))));
            }
        }
    }
}
