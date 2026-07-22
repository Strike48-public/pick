//! Pick Crux core — a pure crux_core App modeling Easy Mode, sibling to the
//! Dioxus app. Sans-I/O: all network work happens in pick-crux-middleware.

use crux_core::{macros::effect, render::RenderOperation, App, Command};
use facet::Facet;
use serde::{Deserialize, Serialize};

pub mod effect;
pub mod model;
pub mod update;
pub mod view;

pub use effect::{ConversationDelta, PentestOperation};
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
    OpenDocument(String),
    CloseDocument,
    CreateShareLink(String),
    RetrySignIn,
    DismissError,
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
            show_scan_card: model.messages.is_empty(),
            conversation_docs: model.conversation_docs.clone(),
            all_documents: model.all_documents.clone(),
            history: model.history.clone(),
            open_document: model.open_document.clone(),
            needs_sign_in: matches!(model.phase, model::Phase::NeedsSignIn),
            error: model.error.clone(),
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
        let mut m = Model::default();
        m.phase = model::Phase::NeedsSignIn;
        let vm = app.view(&m);
        assert!(vm.needs_sign_in);
        assert_eq!(vm.screen, view::Screen::NeedsSignIn);
    }
}
