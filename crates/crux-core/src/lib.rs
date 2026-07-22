//! Pick Crux core — a pure crux_core App modeling Easy Mode, sibling to the
//! Dioxus app. Sans-I/O: all network work happens in pick-crux-middleware.

use crux_core::{macros::effect, render::RenderOperation, App, Command};
use facet::Facet;
use serde::{Deserialize, Serialize};

pub mod model;
pub mod view;

pub use model::Model;
pub use view::ViewModel;

#[effect(facet_typegen)]
#[derive(Debug)]
pub enum Effect {
    Render(RenderOperation),
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub enum Event {
    NoOp,
}

#[derive(Default)]
pub struct PickApp;

impl App for PickApp {
    type Event = Event;
    type Model = Model;
    type ViewModel = ViewModel;
    type Effect = Effect;

    fn update(&self, event: Event, _model: &mut Model) -> Command<Effect, Event> {
        match event {
            Event::NoOp => crux_core::render::render(),
        }
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
