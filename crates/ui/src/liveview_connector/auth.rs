//! OTT approval flow, credentials handling, and token refresh logic.

use pentest_core::terminal::TerminalLine;
use std::sync::atomic::Ordering;
use strike48_connector::OttProvider;
use strike48_proto::proto::CredentialsIssued;

use super::{ConnectorEvent, LiveViewConnector};
use crate::components::ConnectingStep;

/// Call the pre-approve API to create a One-Time Token from a Keycloak JWT.
///
/// Returns `(ott_token, matrix_api_url)` on success.  The OTT can then be
/// fed directly into `OttProvider::register_with_ott` so the connector
/// self-registers without requiring manual admin approval.
async fn fetch_pre_approval_ott(api_url: &str, bearer_token: &str) -> Option<serde_json::Value> {
    let tls_insecure = std::env::var("MATRIX_TLS_INSECURE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(tls_insecure)
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .ok()?;

    let url = format!("{}/api/connectors/pre-approve", api_url.trim_end_matches('/'));
    let body = serde_json::json!({
        "connector_type": "pentest-connector",
        "ttl_minutes": 15,
        "notes": "Auto-issued by Android connector",
    });

    tracing::info!("[PreApprove] POST {} (bearer len={})", url, bearer_token.len());

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", bearer_token))
        .json(&body)
        .send()
        .await
        .ok()?;

    let status = resp.status();
    if !status.is_success() {
        let err_body = resp.text().await.unwrap_or_default();
        tracing::warn!("[PreApprove] Failed ({}): {}", status, err_body);
        return None;
    }

    let json: serde_json::Value = resp.json().await.ok()?;
    tracing::info!(
        "[PreApprove] OTT created: token_prefix={}, tenant={}",
        json["token"].as_str().map(|t| &t[..std::cmp::min(8, t.len())]).unwrap_or("?"),
        json["tenant_id"].as_str().unwrap_or("?"),
    );
    Some(json)
}

/// Fetch the tenant ID from the Matrix API using a `userDetails` GraphQL query.
/// Same approach as StrikeHub — extracts `details.domain.id` from the response.
async fn fetch_tenant_id(api_url: &str, token: &str) -> Option<String> {
    let tls_insecure = std::env::var("MATRIX_TLS_INSECURE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(tls_insecure)
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;

    let url = format!("{}/api/v1alpha/graphql", api_url.trim_end_matches('/'));
    let query = serde_json::json!({ "query": "query { userDetails { details } }" });

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", token))
        .json(&query)
        .send()
        .await
        .ok()?;

    let body = resp.text().await.ok()?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    let details = v.pointer("/data/userDetails/details")?;
    let details = if let Some(s) = details.as_str() {
        serde_json::from_str::<serde_json::Value>(s).ok()?
    } else {
        details.clone()
    };
    let tenant = details.pointer("/domain/id")?.as_str().map(String::from);
    if let Some(ref t) = tenant {
        tracing::info!("[fetch_tenant_id] resolved: {}", t);
    }
    tenant
}

impl LiveViewConnector {
    /// Pre-connection auth: run browser OAuth and resolve tenant BEFORE connecting.
    ///
    /// On Android (and other environments without K8s secrets / OTT), the connector
    /// must register with the correct tenant_id from the first WebSocket message.
    /// This method runs the browser OAuth flow early, resolves the real tenant from
    /// the API, and updates `self.config` so `build_registration_message` uses the
    /// correct tenant on the first attempt.
    pub(crate) async fn try_early_browser_auth(&mut self) -> bool {
        let api_url = self.derive_matrix_api_url();
        tracing::info!(
            "[EarlyAuth] Attempting browser OAuth before connection ({})",
            api_url
        );
        self.send_event(ConnectorEvent::Log(TerminalLine::info(
            "Authenticating via browser...",
        )));

        match pentest_core::matrix::fetch_matrix_token_browser(&api_url).await {
            Ok(token) => {
                tracing::info!(
                    "[EarlyAuth] Got token via browser OAuth (len={})",
                    token.len(),
                );

                // Resolve tenant from the API using the fresh token
                if let Some(tenant) = fetch_tenant_id(&api_url, &token).await {
                    tracing::info!("[EarlyAuth] Resolved tenant: {}", tenant);
                    self.config.tenant_id = tenant.clone();
                    crate::session::set_tenant_id(&tenant);
                }

                // Set Matrix credentials for the chat panel (browser token)
                crate::liveview_server::set_matrix_credentials(&api_url, &token);
                crate::session::set_auth_token(&token);
                self.send_event(ConnectorEvent::MatrixTokenObtained {
                    auth_token: token.clone(),
                    api_url: api_url.clone(),
                });

                // Auto-approval: use the browser JWT to create a pre-approved OTT,
                // then register with it to get proper connector credentials (keypair + JWT).
                // This avoids the need for manual admin approval in Studio.
                if let Some(ott_resp) = fetch_pre_approval_ott(&api_url, &token).await {
                    if let Some(ott_token) = ott_resp["token"].as_str() {
                        self.send_event(ConnectorEvent::Log(TerminalLine::info(
                            "Pre-approval token obtained, registering connector...",
                        )));

                        // Write OTT as JSON to the registration-token file so OttProvider
                        // can also find it on subsequent restarts if needed.
                        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                        let ott_dir = format!("{}/.matrix", home);
                        let _ = std::fs::create_dir_all(&ott_dir);
                        let ott_path = format!("{}/registration-token", ott_dir);
                        let _ = std::fs::write(&ott_path, ott_resp.to_string());
                        // Also set env var so OttProvider::has_ott() picks it up immediately
                        std::env::set_var("STRIKE48_REGISTRATION_TOKEN", ott_resp.to_string());
                        // Set the API URL so OttProvider can reach the registration endpoint
                        std::env::set_var("STRIKE48_API_URL", &api_url);

                        let connector_type = "pentest-connector".to_string();
                        let instance_id = self.config.instance_id.clone();
                        let mut ott_provider = OttProvider::new(
                            Some(connector_type.clone()),
                            Some(instance_id.clone()),
                        );

                        match ott_provider.register_with_ott(&connector_type, Some(&instance_id)).await {
                            Ok(creds) => {
                                tracing::info!(
                                    "[EarlyAuth] Self-registration successful: client_id={}",
                                    creds.client_id
                                );
                                self.send_event(ConnectorEvent::Log(TerminalLine::success(
                                    format!("Connector registered: {}", creds.client_id),
                                )));

                                // Get a proper connector JWT
                                match ott_provider.get_token().await {
                                    Ok(jwt) => {
                                        tracing::info!(
                                            "[EarlyAuth] Got connector JWT (len={})",
                                            jwt.len()
                                        );
                                        self.config.auth_token = jwt.clone();
                                        self.send_event(ConnectorEvent::CredentialsUpdated {
                                            auth_token: jwt,
                                            api_url: api_url.clone(),
                                        });
                                        *self.ott_provider.write().await = Some(ott_provider);
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "[EarlyAuth] JWT fetch after registration failed: {}",
                                            e
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("[EarlyAuth] OTT self-registration failed: {}", e);
                                self.send_event(ConnectorEvent::Log(TerminalLine::info(format!(
                                    "Self-registration failed ({}), will wait for approval",
                                    e
                                ))));
                            }
                        }

                        // Clean up the OTT file (one-time use)
                        let _ = std::fs::remove_file(&ott_path);
                        std::env::remove_var("STRIKE48_REGISTRATION_TOKEN");
                    }
                } else {
                    self.send_event(ConnectorEvent::Log(TerminalLine::success(
                        "Browser auth completed (pre-approval unavailable), connecting...",
                    )));
                }

                true
            }
            Err(e) => {
                tracing::warn!("[EarlyAuth] browser OAuth failed: {}", e);
                self.send_event(ConnectorEvent::Log(TerminalLine::info(format!(
                    "Browser auth failed ({}), will retry after registration",
                    e
                ))));
                false
            }
        }
    }

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

                // Resolve tenant from the API using the fresh token
                if let Some(tenant) = fetch_tenant_id(&api_url, &token).await {
                    tracing::info!("[FetchTokenFallback] Resolved tenant: {}", tenant);
                    self.config.tenant_id = tenant.clone();
                    crate::session::set_tenant_id(&tenant);
                }

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
