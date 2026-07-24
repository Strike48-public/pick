//! Pick Crux core — a pure crux_core App modeling Easy Mode, sibling to the
//! Dioxus app. Sans-I/O: all network work happens in pick-crux-middleware.

use crux_core::{macros::effect, render::RenderOperation, App, Command};
use facet::Facet;
use serde::{Deserialize, Serialize};

pub mod effect;
pub mod markdown;
pub mod model;
pub mod update;
pub mod view;

pub use effect::{ConversationDelta, PentestOperation};
pub use markdown::{MarkdownBlock, Span, SpanStyle};
pub use model::Model;
pub use view::ViewModel;

#[effect(facet_typegen)]
#[derive(Debug)]
pub enum Effect {
    Render(RenderOperation),
    Pentest(PentestOperation),
}

// FFI-friendly outcome types (Result<T,E> is not Facet-serializable for typegen)
#[derive(Facet, Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct SignInOutcome {
    pub token: Option<String>,
    pub error: Option<String>,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct ConnectOutcome {
    pub ok: Option<()>,
    pub err: Option<String>,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct ScanOutcome {
    pub conversation_id: Option<String>,
    pub error: Option<String>,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct DeltaOutcome {
    pub delta: Option<ConversationDelta>,
    pub error: Option<String>,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct ConversationsOutcome {
    pub conversations: Option<Vec<view::ConversationRef>>,
    pub error: Option<String>,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct LoadConversationOutcome {
    pub messages: Option<Vec<view::MessageView>>,
    pub error: Option<String>,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct DocumentsOutcome {
    pub documents: Option<Vec<view::DocRef>>,
    pub error: Option<String>,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct DocumentContentOutcome {
    pub content: Option<String>,
    pub error: Option<String>,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub struct ShareLinkOutcome {
    pub url: Option<String>,
    /// Browser-preview transform of `url`; carried alongside so the App can set
    /// `DocView::preview_url` without recomputing across the FFI boundary.
    pub preview_url: Option<String>,
    /// Per-network share destinations built by the middleware.
    pub social_links: Vec<view::SocialLink>,
    pub error: Option<String>,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub enum Event {
    // user intents
    StartScan,
    SendMessage(String),
    NewChat,
    OpenHistory,
    CloseHistory,
    SelectConversation(String),
    /// User opened the Reports list — (re)fetch all documents on demand, so the
    /// list is populated even without a just-completed scan.
    OpenDocuments,
    OpenDocument(String),
    CloseDocument,
    CreateShareLink(String),
    RetrySignIn,
    DismissError,
    /// Seed persisted settings at startup from the shell's native store. Sent
    /// once before the user interacts, so the ViewModel + telemetry reflect the
    /// saved opt-out choice.
    SeedSettings {
        telemetry_enabled: bool,
    },
    /// Toggle usage telemetry at runtime (Settings). Flips the core flag and
    /// enables/disables the Sentry client immediately; the shell persists it.
    SetTelemetryEnabled(bool),
    /// Sign out: clears in-core session/conversation state and returns to the
    /// sign-in screen. The shell separately clears its persisted token.
    Logout,
    // effect results
    SignInResult(SignInOutcome),
    ConnectResult(ConnectOutcome),
    ScanResult(ScanOutcome),
    Delta(DeltaOutcome),
    ConversationsResult(ConversationsOutcome),
    LoadConversationResult(LoadConversationOutcome),
    DocumentsResult(DocumentsOutcome),
    DocumentContentResult(DocumentContentOutcome),
    ShareLinkResult(ShareLinkOutcome),
}

#[derive(Default)]
pub struct PickApp;

impl App for PickApp {
    type Event = Event;
    type Model = Model;
    type ViewModel = ViewModel;
    type Effect = Effect;

    fn update(&self, event: Event, model: &mut Model) -> Command<Effect, Event> {
        update::update(self, event, model)
    }

    fn view(&self, model: &Model) -> ViewModel {
        ViewModel {
            screen: if model.open_document.is_some() {
                view::Screen::DocViewer
            } else if matches!(model.phase, model::Phase::NeedsSignIn) {
                view::Screen::NeedsSignIn
            } else if model.messages.is_empty() {
                view::Screen::Scan
            } else {
                view::Screen::Chat
            },
            connection: view::ConnectionView {
                phase: model.phase.to_view(),
                label: model.phase.label().to_string(),
            },
            messages: model.messages.clone(),
            scan_in_progress: model.scan_active,
            show_scan_card: !model.scan_active
                && model.messages.is_empty()
                && model.conversation_id.is_none(),
            conversation_docs: model.conversation_docs.clone(),
            all_documents: model.all_documents.clone(),
            history: model.history.clone(),
            open_document: model.open_document.clone(),
            needs_sign_in: matches!(model.phase, model::Phase::NeedsSignIn),
            error: model.error.clone(),
            tool_calls: model.tool_calls.clone(),
            agent_activity: model.activity.clone(),
            activity_label: model.activity.label().to_string(),
            notice: model.notice.clone(),
            next_steps: model.next_steps.clone(),
            settings: view::SettingsView {
                telemetry_enabled: model.telemetry_enabled,
            },
        }
    }
}

#[cfg(test)]
mod view_tests {
    use super::*;
    #[test]
    fn empty_model_shows_scan_screen_with_card() {
        let app = PickApp;
        let vm = app.view(&Model::default());
        assert_eq!(vm.screen, view::Screen::Scan);
        assert!(vm.show_scan_card);
        assert!(!vm.scan_in_progress);
    }
    #[test]
    fn needs_sign_in_phase_projects_needs_sign_in() {
        let app = PickApp;
        let m = Model {
            phase: model::Phase::NeedsSignIn,
            ..Default::default()
        };
        let vm = app.view(&m);
        assert!(vm.needs_sign_in);
        assert_eq!(vm.screen, view::Screen::NeedsSignIn);
    }
}
