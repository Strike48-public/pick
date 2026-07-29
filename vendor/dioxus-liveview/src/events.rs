//! Convert a serialized event to an event trigger

use dioxus_html::*;

use crate::element::LiveviewElement;

pub(crate) struct SerializedHtmlEventConverter;

impl HtmlEventConverter for SerializedHtmlEventConverter {
    fn convert_animation_data(&self, event: &PlatformEventData) -> AnimationData {
        event
            .downcast::<SerializedAnimationData>()
            .cloned()
            .unwrap()
            .into()
    }

    fn convert_cancel_data(&self, event: &PlatformEventData) -> CancelData {
        event
            .downcast::<SerializedCancelData>()
            .cloned()
            .unwrap()
            .into()
    }

    fn convert_clipboard_data(&self, event: &PlatformEventData) -> ClipboardData {
        event
            .downcast::<SerializedClipboardData>()
            .cloned()
            .unwrap()
            .into()
    }

    fn convert_composition_data(&self, event: &PlatformEventData) -> CompositionData {
        event
            .downcast::<SerializedCompositionData>()
            .cloned()
            .unwrap()
            .into()
    }

    fn convert_drag_data(&self, event: &PlatformEventData) -> DragData {
        event
            .downcast::<SerializedDragData>()
            .cloned()
            .unwrap()
            .into()
    }

    fn convert_focus_data(&self, event: &PlatformEventData) -> FocusData {
        event
            .downcast::<SerializedFocusData>()
            .cloned()
            .unwrap()
            .into()
    }

    fn convert_form_data(&self, event: &PlatformEventData) -> FormData {
        // PATCHED (Strike48/pick): upstream 0.7.9 does `.unwrap()` here, which
        // aborts the whole process when the downcast is `None`. On the desktop
        // WebView2 transport an `oninput`/`onchange` event can arrive without a
        // `SerializedFormData` payload (the serialized shape doesn't round-trip
        // to the Form variant), so the unwrap panics on the first keystroke in a
        // text field. Fall back to an empty form instead of crashing; the worst
        // case is one input event with empty value/values rather than a dead app.
        // Remove once fixed upstream (still broken as of 0.8.0-alpha).
        let data = event
            .downcast::<SerializedFormData>()
            .cloned()
            .unwrap_or_else(|| SerializedFormData::new(String::new(), Vec::new()));
        data.into()
    }

    fn convert_image_data(&self, event: &PlatformEventData) -> ImageData {
        event
            .downcast::<SerializedImageData>()
            .cloned()
            .unwrap()
            .into()
    }

    fn convert_keyboard_data(&self, event: &PlatformEventData) -> KeyboardData {
        event
            .downcast::<SerializedKeyboardData>()
            .cloned()
            .unwrap()
            .into()
    }

    fn convert_media_data(&self, event: &PlatformEventData) -> MediaData {
        event
            .downcast::<SerializedMediaData>()
            .cloned()
            .unwrap()
            .into()
    }

    fn convert_mounted_data(&self, event: &PlatformEventData) -> MountedData {
        event.downcast::<LiveviewElement>().cloned().unwrap().into()
    }

    fn convert_mouse_data(&self, event: &PlatformEventData) -> MouseData {
        event
            .downcast::<SerializedMouseData>()
            .cloned()
            .unwrap()
            .into()
    }

    fn convert_pointer_data(&self, event: &PlatformEventData) -> PointerData {
        event
            .downcast::<SerializedPointerData>()
            .cloned()
            .unwrap()
            .into()
    }

    fn convert_resize_data(&self, event: &PlatformEventData) -> ResizeData {
        event
            .downcast::<SerializedResizeData>()
            .cloned()
            .unwrap()
            .into()
    }

    fn convert_scroll_data(&self, event: &PlatformEventData) -> ScrollData {
        event
            .downcast::<SerializedScrollData>()
            .cloned()
            .unwrap()
            .into()
    }

    fn convert_selection_data(&self, event: &PlatformEventData) -> SelectionData {
        event
            .downcast::<SerializedSelectionData>()
            .cloned()
            .unwrap()
            .into()
    }

    fn convert_toggle_data(&self, event: &PlatformEventData) -> ToggleData {
        event
            .downcast::<SerializedToggleData>()
            .cloned()
            .unwrap()
            .into()
    }

    fn convert_touch_data(&self, event: &PlatformEventData) -> TouchData {
        event
            .downcast::<SerializedTouchData>()
            .cloned()
            .unwrap()
            .into()
    }

    fn convert_transition_data(&self, event: &PlatformEventData) -> TransitionData {
        event
            .downcast::<SerializedTransitionData>()
            .cloned()
            .unwrap()
            .into()
    }

    fn convert_visible_data(&self, event: &PlatformEventData) -> VisibleData {
        event
            .downcast::<SerializedVisibleData>()
            .cloned()
            .unwrap()
            .into()
    }

    fn convert_wheel_data(&self, event: &PlatformEventData) -> WheelData {
        event
            .downcast::<SerializedWheelData>()
            .cloned()
            .unwrap()
            .into()
    }
}
