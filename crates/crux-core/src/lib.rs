//! Pick Crux core — a pure crux_core App modeling Easy Mode, sibling to the
//! Dioxus app. Sans-I/O: all network work happens in pick-crux-middleware.

use crux_core::{macros::effect, render::RenderOperation, App, Command};
use facet::Facet;
use serde::{Deserialize, Serialize};

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
pub struct Model {}

#[derive(Facet, Serialize, Deserialize, Clone, Default, Debug)]
pub struct ViewModel {}

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

    fn view(&self, _model: &Model) -> ViewModel {
        ViewModel {}
    }
}
