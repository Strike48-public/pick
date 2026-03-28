//! Icon re-exports from `lucide-dioxus` and brand assets.
//!
//! All UI components import icons from here. Each icon is a Dioxus
//! component that accepts `size: usize` (among other props).

pub use lucide_dioxus::{
    Bolt, ChevronDown, CircleQuestionMark, Download, FileText, Folder, History, House, Info,
    LayoutGrid, Menu, MessageCircle, MessageSquare, Network, Palette, Plus, ScrollText, Search,
    Settings, Shield, Terminal, User, Wifi, Wrench, X,
};

// ---------------------------------------------------------------------------
// Brand / logo (no lucide equivalent — kept as raw SVG)
// ---------------------------------------------------------------------------

pub const STRIKE48_SIDEBAR_LOGO_SVG: &str = include_str!("../assets/icons/strike48-logo.svg");
