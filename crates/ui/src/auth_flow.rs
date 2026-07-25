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
    /// Startup: SDK connector credentials exist on disk.
    CredsFound,
    /// Startup: no connector credentials on disk.
    CredsAbsent,
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

/// Pure transition function. `easy` is the resolved easy-mode flag and `auto`
/// is the persisted `auto_connect` setting; together they decide the startup
/// branch. In expert mode (`easy == false`) the caller does not route through
/// this machine, but `reduce` still returns a sensible value.
pub fn reduce(state: AuthFlow, event: AuthEvent, easy: bool, auto: bool) -> AuthFlow {
    use AuthEvent as E;
    use AuthFlow as S;

    match (state, event) {
        // ---- Startup ------------------------------------------------------
        // A restored token is trusted optimistically: show the shell, no
        // overlay. A later ChatAuthDead downgrades to Failed { reauth }.
        (S::Restoring, E::Restored { have_token: true }) => S::Connected { chat_ready: false },
        // No token: decide by creds + auto_connect (mirrors plg_connect_decision).
        (S::Restoring, E::Restored { have_token: false }) => S::Disconnected,
        (S::Disconnected, E::CredsFound) if auto => S::Registering(ConnectingStep::Connecting),
        (S::Disconnected, E::CredsFound) => S::AwaitingGesture,
        (S::Disconnected, E::CredsAbsent) => S::AwaitingGesture,

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
        (S::SigningIn, E::TokenFailed(reason)) => S::Failed { reason, reauth: true },

        // ---- Connector connect -------------------------------------------
        (S::Registering(_), E::ConnectorStep(step)) => S::Registering(step),
        (S::Registering(_), E::ConnectorRegistered) => S::Connected { chat_ready: false },

        // ---- Connected ----------------------------------------------------
        (S::Connected { .. }, E::ChatReady) => S::Connected { chat_ready: true },
        (S::Connected { .. }, E::ChatAuthDead) => S::Failed {
            reason: "Your session expired".to_string(),
            reauth: true,
        },

        // ---- Global transitions ------------------------------------------
        (_, E::LoggedOut) => S::AwaitingGesture,
        (_, E::Disconnected) => S::Disconnected,

        // Anything else is a no-op (keep current state). `easy` is reserved for
        // future expert/easy divergence; unused branches keep it referenced.
        (state, _) => {
            let _ = easy;
            state
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::components::ConnectingStep;

    // The double-sign-in fix: SignInRequested advances only from AwaitingGesture.
    #[test]
    fn sign_in_requested_is_idempotent() {
        assert_eq!(
            reduce(AuthFlow::AwaitingGesture, AuthEvent::SignInRequested, true, false),
            AuthFlow::SigningIn
        );
        // From SigningIn (already in flight) it's a no-op.
        assert_eq!(
            reduce(AuthFlow::SigningIn, AuthEvent::SignInRequested, true, false),
            AuthFlow::SigningIn
        );
        // From Connected it's a no-op.
        assert_eq!(
            reduce(
                AuthFlow::Connected { chat_ready: true },
                AuthEvent::SignInRequested,
                true,
                false
            ),
            AuthFlow::Connected { chat_ready: true }
        );
    }

    // Restored token → optimistic Connected (no overlay).
    #[test]
    fn restored_token_is_optimistically_connected() {
        assert_eq!(
            reduce(AuthFlow::Restoring, AuthEvent::Restored { have_token: true }, true, true),
            AuthFlow::Connected { chat_ready: false }
        );
    }

    // Dead token downgrades Connected → Failed { reauth }.
    #[test]
    fn chat_auth_dead_downgrades_to_failed_reauth() {
        let s = reduce(
            AuthFlow::Connected { chat_ready: false },
            AuthEvent::ChatAuthDead,
            true,
            true,
        );
        assert!(matches!(s, AuthFlow::Failed { reauth: true, .. }));
    }

    // No token at startup: creds + auto → silent connect; else → overlay.
    #[test]
    fn startup_no_token_branches_on_creds_and_auto() {
        let disc = reduce(AuthFlow::Restoring, AuthEvent::Restored { have_token: false }, true, true);
        assert_eq!(disc, AuthFlow::Disconnected);
        // creds present + auto → auto-connect
        assert_eq!(
            reduce(AuthFlow::Disconnected, AuthEvent::CredsFound, true, true),
            AuthFlow::Registering(ConnectingStep::Connecting)
        );
        // creds present but auto off → overlay (user must tap)
        assert_eq!(
            reduce(AuthFlow::Disconnected, AuthEvent::CredsFound, true, false),
            AuthFlow::AwaitingGesture
        );
        // no creds → overlay
        assert_eq!(
            reduce(AuthFlow::Disconnected, AuthEvent::CredsAbsent, true, true),
            AuthFlow::AwaitingGesture
        );
    }

    // Sign-in → token → registering → connected happy path.
    #[test]
    fn happy_path_signin_to_connected() {
        let s = AuthFlow::AwaitingGesture;
        let s = reduce(s, AuthEvent::SignInRequested, true, false);
        assert_eq!(s, AuthFlow::SigningIn);
        let s = reduce(s, AuthEvent::TokenObtained, true, false);
        assert_eq!(s, AuthFlow::Registering(ConnectingStep::SigningIn));
        let s = reduce(s, AuthEvent::ConnectorStep(ConnectingStep::Registering), true, false);
        assert_eq!(s, AuthFlow::Registering(ConnectingStep::Registering));
        let s = reduce(s, AuthEvent::ConnectorRegistered, true, false);
        assert_eq!(s, AuthFlow::Connected { chat_ready: false });
        let s = reduce(s, AuthEvent::ChatReady, true, false);
        assert_eq!(s, AuthFlow::Connected { chat_ready: true });
    }

    // Logout always returns to the sign-in overlay.
    #[test]
    fn logout_returns_to_awaiting_gesture() {
        assert_eq!(
            reduce(AuthFlow::Connected { chat_ready: true }, AuthEvent::LoggedOut, true, true),
            AuthFlow::AwaitingGesture
        );
    }

    // Token failure during sign-in → Failed { reauth }.
    #[test]
    fn token_failure_is_reauth_failure() {
        let s = reduce(AuthFlow::SigningIn, AuthEvent::TokenFailed("boom".into()), true, false);
        assert_eq!(s, AuthFlow::Failed { reason: "boom".into(), reauth: true });
    }

    // Failed { reauth } can retry sign-in (the button is not a dead-end).
    #[test]
    fn failed_reauth_can_retry_sign_in() {
        assert_eq!(
            reduce(
                AuthFlow::Failed { reason: "expired".into(), reauth: true },
                AuthEvent::SignInRequested,
                true,
                false
            ),
            AuthFlow::SigningIn
        );
    }

    // Disconnected can sign in (cancel on ConnectingScreen while SigningIn
    // dispatches Disconnected; must not be a dead-end).
    #[test]
    fn disconnected_can_sign_in() {
        assert_eq!(
            reduce(AuthFlow::Disconnected, AuthEvent::SignInRequested, true, false),
            AuthFlow::SigningIn
        );
    }
}
