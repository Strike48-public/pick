//! Icon re-exports from `lucide-dioxus` and brand assets.
//!
//! All UI components import icons from here. Each icon is a Dioxus
//! component that accepts `size: usize` (among other props).

pub use lucide_dioxus::{
    Bolt, ChevronDown, ChevronLeft, CircleQuestionMark, Download, FileText, Folder, History, House,
    Info, LayoutGrid, Lock, LogOut, Menu, MessageCircle, MessageSquare, Network, Palette, Plus,
    ScrollText, Search, Settings, Shield, Terminal, User, Wifi, Wrench, X,
};

// ---------------------------------------------------------------------------
// Brand / logo (no lucide equivalent — kept as raw SVG)
// ---------------------------------------------------------------------------

pub const STRIKE48_SIDEBAR_LOGO_SVG: &str = include_str!("../assets/icons/strike48-logo.svg");

/// Square Strike48 "S" monogram for the Easy Mode co-brand badge. The full
/// logo (`STRIKE48_SIDEBAR_LOGO_SVG`) is a wide wordmark; this is a compact
/// glyph sized for a ~30px rounded badge. Uses `stroke="currentColor"` so the
/// badge can paint it white.
pub const STRIKE48_S_BADGE_SVG: &str = include_str!("../assets/icons/strike48-s-badge.svg");
