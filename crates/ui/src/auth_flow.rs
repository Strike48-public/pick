//! Explicit state machine for the easy-mode login/connection flow.
//!
//! This is the single source of truth for "where is the user in signing in and
//! connecting".
//!
//! Pure and Dioxus-free so it can be unit-tested exhaustively. The UI layer
//! (`connector_app`) holds a `Signal<AuthFlow>` and mutates it ONLY through a
//! `dispatch(event)` closure that calls [`reduce`].

use crate::components::ConnectingStep;

/// Where the easy-mode user is in the sign-in + connect lifecycle.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthFlow {
    /// Startup, before the first decision is made.
    Restoring,
    /// Transient disconnected state; startup logic decides the next step.
    Disconnected,
    /// Sign-in overlay shown, waiting for the user's tap.
    AwaitingGesture,
    /// Browser / native OAuth is in flight.
    SigningIn,
    /// Connector `connect_and_run` in progress, post-token. Carries the
    /// sub-step for the connecting screen.
    Registering(ConnectingStep),
    /// Connector registered. `chat_ready` folds "agents loaded".
    Connected { chat_ready: bool },
    /// Sign-in/connect failed. `reauth` = the chat token is dead and we should
    /// offer the sign-in overlay again.
    Failed { reason: String, reauth: bool },
}

/// Events that drive [`AuthFlow`] transitions. Emitted by the UI layer from
/// user actions, the connector event loop, and the chat panel.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthEvent {
    /// Startup: whether a persisted chat token was restored.
    Restored { have_token: bool },
    /// The user tapped the "Sign in" button. The ONLY way to reach SigningIn.
    SignInRequested,
    /// A chat token was obtained (browser/native OAuth returned).
    TokenObtained,
    /// OAuth failed.
    TokenFailed(String),
    /// Connector connect progressed to a sub-step.
    ConnectorStep(ConnectingStep),
    /// Connector finished registering.
    ConnectorRegistered,
    /// Agents loaded — chat is usable.
    ChatReady,
    /// The chat token is dead (server rejected it).
    ChatAuthDead,
    /// The user logged out.
    LoggedOut,
    /// The connector transport dropped.
    Disconnected,
}

/// Pure transition function from the current [`AuthFlow`] state and an
/// [`AuthEvent`] to the next state. Startup routes purely on token presence and
/// the connector-registration steps; the persisted `auto_connect` setting is
/// consulted by the caller (as the "remember me" flag), not here. In expert mode
/// the caller does not route through this machine, but `reduce` still returns a
/// sensible value.
pub fn reduce(state: AuthFlow, event: AuthEvent) -> AuthFlow {
    use AuthEvent as E;
    use AuthFlow as S;

    match (state, event) {
        // ---- Startup ------------------------------------------------------
        // The chat token gates the easy-mode UI (connector registration creds
        // are separate and do NOT count). With a restored token we go straight
        // to connecting the connector; without one we always show the sign-in
        // overlay — the sign-in gesture performs OAuth AND connects together.
        (S::Restoring, E::Restored { have_token: true }) => {
            S::Registering(ConnectingStep::Connecting)
        }
        (S::Restoring, E::Restored { have_token: false }) => S::AwaitingGesture,

        // ---- The gesture (idempotent) ------------------------------------
        // Failed{reauth:true} and Disconnected can retry sign-in; any other
        // state is unchanged, so a duplicate dispatch cannot launch a second
        // sign-in from SigningIn/Connected.
        (S::Failed { reauth: true, .. }, E::SignInRequested) => S::SigningIn,
        (S::Disconnected, E::SignInRequested) => S::SigningIn,
        (S::AwaitingGesture, E::SignInRequested) => S::SigningIn,
        (other, E::SignInRequested) => other,

        // ---- Sign-in in flight -------------------------------------------
        (S::SigningIn, E::TokenObtained) => S::Registering(ConnectingStep::SigningIn),
        (S::SigningIn, E::TokenFailed(reason)) | (S::Registering(_), E::TokenFailed(reason)) => {
            S::Failed {
                reason,
                reauth: true,
            }
        }

        // ---- Connector connect -------------------------------------------
        (S::Registering(_), E::ConnectorStep(step)) => S::Registering(step),
        (S::Registering(_), E::ConnectorRegistered) => S::Connected { chat_ready: false },

        // ---- Connected ----------------------------------------------------
        (S::Connected { .. }, E::ChatReady) => S::Connected { chat_ready: true },
        // A dead chat session is terminal from any in-flight or connected state,
        // not just Connected. A token restored at startup is only checked for JWT
        // expiry, not server-side validity, so an unexpired-but-dead token can
        // surface ChatAuthDead while the flow is still SigningIn/Registering (the
        // ChatPanel agent-fetch runs concurrently with connector registration).
        // Handling it only from Connected would drop the event and strand the flow
        // in Registering. Route to Failed{reauth} from all three.
        (S::Connected { .. }, E::ChatAuthDead)
        | (S::Registering(_), E::ChatAuthDead)
        | (S::SigningIn, E::ChatAuthDead) => S::Failed {
            reason: "Your session expired".to_string(),
            reauth: true,
        },

        // ---- Global transitions ------------------------------------------
        (_, E::LoggedOut) => S::AwaitingGesture,
        (_, E::Disconnected) => S::Disconnected,

        // Anything else is a no-op (keep current state).
        (state, _) => state,
    }
}

/// Whether the easy-mode "offline" overlay (sign-in / retry / change-server)
/// should be shown, given the flow state and whether the change-server modal is
/// open.
///
/// The offline screen and the change-server modal are BOTH opaque, full-screen
/// `easy-overlay` layers at the same z-index. If both render at once they stack
/// ambiguously and clicks on the modal's form (notably Save) land on the wrong
/// layer — the modal feels dead. `flow()` stays in an offline state while the
/// modal is open (opening it is not an auth transition), so the modal-open flag
/// must explicitly suppress the offline screen. This is the single invariant
/// that guards against the two overlays coexisting.
pub fn should_show_offline_screen(flow: &AuthFlow, endpoint_modal_open: bool) -> bool {
    if endpoint_modal_open {
        return false;
    }
    matches!(
        flow,
        AuthFlow::AwaitingGesture
            | AuthFlow::Failed { reauth: true, .. }
            | AuthFlow::Disconnected
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::components::ConnectingStep;

    // The double-sign-in fix: SignInRequested advances only from AwaitingGesture.
    #[test]
    fn sign_in_requested_is_idempotent() {
        assert_eq!(
            reduce(AuthFlow::AwaitingGesture, AuthEvent::SignInRequested,),
            AuthFlow::SigningIn
        );
        // From SigningIn (already in flight) it's a no-op.
        assert_eq!(
            reduce(AuthFlow::SigningIn, AuthEvent::SignInRequested),
            AuthFlow::SigningIn
        );
        // From Connected it's a no-op.
        assert_eq!(
            reduce(
                AuthFlow::Connected { chat_ready: true },
                AuthEvent::SignInRequested,
            ),
            AuthFlow::Connected { chat_ready: true }
        );
    }

    // Restored token → Registering (will connect the connector).
    #[test]
    fn restored_token_starts_registering() {
        assert_eq!(
            reduce(
                AuthFlow::Restoring,
                AuthEvent::Restored { have_token: true },
            ),
            AuthFlow::Registering(ConnectingStep::Connecting)
        );
    }

    // Dead token downgrades Connected → Failed { reauth }.
    #[test]
    fn chat_auth_dead_downgrades_to_failed_reauth() {
        let s = reduce(
            AuthFlow::Connected { chat_ready: false },
            AuthEvent::ChatAuthDead,
        );
        assert!(matches!(s, AuthFlow::Failed { reauth: true, .. }));
    }

    // A dead chat session must not be dropped while the flow is still connecting.
    // A restored-but-server-dead token can surface ChatAuthDead during SigningIn
    // or Registering (chat agent-fetch runs concurrently with registration);
    // both must route to Failed{reauth} rather than stranding in Registering.
    #[test]
    fn chat_auth_dead_from_in_flight_states_fails_reauth() {
        for state in [
            AuthFlow::SigningIn,
            AuthFlow::Registering(ConnectingStep::SigningIn),
            AuthFlow::Registering(ConnectingStep::Connecting),
            AuthFlow::Registering(ConnectingStep::Registering),
        ] {
            let s = reduce(state.clone(), AuthEvent::ChatAuthDead);
            assert!(
                matches!(s, AuthFlow::Failed { reauth: true, .. }),
                "ChatAuthDead from {state:?} should fail-reauth, got {s:?}"
            );
        }
    }

    // No token at startup: always show sign-in overlay.
    #[test]
    fn startup_no_token_awaits_gesture() {
        assert_eq!(
            reduce(
                AuthFlow::Restoring,
                AuthEvent::Restored { have_token: false },
            ),
            AuthFlow::AwaitingGesture
        );
        assert_eq!(
            reduce(
                AuthFlow::Restoring,
                AuthEvent::Restored { have_token: false },
            ),
            AuthFlow::AwaitingGesture
        );
    }

    // Sign-in → token → registering → connected happy path.
    #[test]
    fn happy_path_signin_to_connected() {
        let s = AuthFlow::AwaitingGesture;
        let s = reduce(s, AuthEvent::SignInRequested);
        assert_eq!(s, AuthFlow::SigningIn);
        let s = reduce(s, AuthEvent::TokenObtained);
        assert_eq!(s, AuthFlow::Registering(ConnectingStep::SigningIn));
        let s = reduce(s, AuthEvent::ConnectorStep(ConnectingStep::Registering));
        assert_eq!(s, AuthFlow::Registering(ConnectingStep::Registering));
        let s = reduce(s, AuthEvent::ConnectorRegistered);
        assert_eq!(s, AuthFlow::Connected { chat_ready: false });
        let s = reduce(s, AuthEvent::ChatReady);
        assert_eq!(s, AuthFlow::Connected { chat_ready: true });
    }

    // Logout always returns to the sign-in overlay.
    #[test]
    fn logout_returns_to_awaiting_gesture() {
        assert_eq!(
            reduce(
                AuthFlow::Connected { chat_ready: true },
                AuthEvent::LoggedOut,
            ),
            AuthFlow::AwaitingGesture
        );
    }

    // Token failure during sign-in → Failed { reauth }.
    #[test]
    fn token_failure_is_reauth_failure() {
        let s = reduce(AuthFlow::SigningIn, AuthEvent::TokenFailed("boom".into()));
        assert_eq!(
            s,
            AuthFlow::Failed {
                reason: "boom".into(),
                reauth: true
            }
        );
    }

    // Failed { reauth } can retry sign-in (the button is not a dead-end).
    #[test]
    fn failed_reauth_can_retry_sign_in() {
        assert_eq!(
            reduce(
                AuthFlow::Failed {
                    reason: "expired".into(),
                    reauth: true
                },
                AuthEvent::SignInRequested,
            ),
            AuthFlow::SigningIn
        );
    }

    // Disconnected can sign in (cancel on ConnectingScreen while SigningIn
    // dispatches Disconnected; must not be a dead-end).
    #[test]
    fn disconnected_can_sign_in() {
        assert_eq!(
            reduce(AuthFlow::Disconnected, AuthEvent::SignInRequested,),
            AuthFlow::SigningIn
        );
    }

    // TokenFailed from Registering must route to Failed{reauth} (not strand in
    // Registering). A registration failure (e.g. server pre-approve returns HTTP 500)
    // fires TokenFailed while in Registering(_); without handling it, the app stays
    // in the connecting screen forever. Mirror the ChatAuthDead precedent.
    #[test]
    fn token_failed_from_registering_fails_reauth() {
        for state in [
            AuthFlow::Registering(ConnectingStep::SigningIn),
            AuthFlow::Registering(ConnectingStep::Connecting),
            AuthFlow::Registering(ConnectingStep::Registering),
        ] {
            let s = reduce(
                state.clone(),
                AuthEvent::TokenFailed("pre-approve 500".into()),
            );
            assert!(
                matches!(s, AuthFlow::Failed { reauth: true, .. }),
                "TokenFailed from {state:?} must fail-reauth (not strand in Registering), got {s:?}"
            );
        }
    }

    // --- Overlay coexistence guard (change-server Save was un-clickable) ---

    // The bug: after logout the flow is AwaitingGesture, so the offline screen
    // renders; opening the change-server modal did NOT hide it, so two opaque
    // same-z-index overlays stacked and Save clicks hit the wrong layer. The
    // modal-open flag must suppress the offline screen.
    #[test]
    fn offline_screen_hidden_while_change_server_modal_open() {
        for flow in [
            AuthFlow::AwaitingGesture,
            AuthFlow::Disconnected,
            AuthFlow::Failed {
                reason: "x".into(),
                reauth: true,
            },
        ] {
            assert!(
                should_show_offline_screen(&flow, false),
                "{flow:?} should show the offline screen when no modal is open"
            );
            assert!(
                !should_show_offline_screen(&flow, true),
                "{flow:?} must NOT show the offline screen while the change-server modal is open \
                 (else it stacks over the modal and eats the Save click)"
            );
        }
    }

    // Non-offline states never show the offline screen regardless of the modal.
    #[test]
    fn offline_screen_hidden_in_connected_and_transient_states() {
        for flow in [
            AuthFlow::Restoring,
            AuthFlow::SigningIn,
            AuthFlow::Registering(ConnectingStep::Connecting),
            AuthFlow::Connected { chat_ready: true },
            // A non-reauth failure is a hard error screen, not the offline overlay.
            AuthFlow::Failed {
                reason: "x".into(),
                reauth: false,
            },
        ] {
            assert!(!should_show_offline_screen(&flow, false), "{flow:?}");
            assert!(!should_show_offline_screen(&flow, true), "{flow:?}");
        }
    }
}
