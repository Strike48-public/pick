//! Native-readiness proof: the Core is drivable across the FFI boundary via
//! crux's built-in `Bridge` (bincode-serialized events/requests/view). This is
//! exactly the byte API a SwiftUI / Jetpack Compose shell calls, so passing
//! here means no bespoke FFI codegen (BoltFFI/UniFFI) is required — crux 0.19
//! ships the whole native path.

use crux_core::bridge::{BincodeFfiFormat, Bridge};
use crux_core::Core;
use pick_crux_core::{Event, PickApp};

#[test]
fn bridge_serializes_view_and_processes_events() {
    let core: Core<PickApp> = Core::new();
    let bridge: Bridge<PickApp, BincodeFfiFormat> = Bridge::new(core);

    // view() -> serialized ViewModel bytes (what the shell renders).
    let mut view_out = Vec::new();
    bridge.view(&mut view_out).expect("view serializes");
    assert!(!view_out.is_empty(), "view produced ViewModel bytes");

    // update(event_bytes) -> serialized effect requests (StartScan asks the
    // shell/middleware to send the scan, so it must produce at least one).
    let event = bincode::serialize(&Event::StartScan).expect("serialize event");
    let mut reqs_out = Vec::new();
    bridge
        .update(&event, &mut reqs_out)
        .expect("update processes the event across FFI");
    assert!(
        !reqs_out.is_empty(),
        "StartScan produced effect request bytes"
    );
}
