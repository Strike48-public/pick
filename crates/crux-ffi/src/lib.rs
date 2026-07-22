//! Stable C ABI over the crux `Bridge`, with in-core effect resolution.
//!
//! # Effect routing (Design A: in-FFI middleware loop)
//!
//! crux 0.19 ships two `Bridge` types:
//!
//!  * [`crux_core::bridge::Bridge`] — the *synchronous* top-level bridge. Its
//!    `update`/`resolve` return the complete `Vec<Request<EffectFfi>>` batch
//!    (bincode bytes) right away.
//!  * [`crux_core::middleware::Bridge`] — a middleware-aware bridge whose
//!    `EffectMiddleware` resolves effects on a background thread and hands
//!    follow-up effects back through an *async callback* (`process_tasks`).
//!
//! We use the **synchronous** top-level bridge and resolve `Pentest` effects
//! ourselves in a loop: after each `update`/`resolve` we deserialize the
//! returned `Requests` batch, run every `Effect::Pentest(op)` through
//! `pick_crux_middleware::map_operation` on an owned tokio runtime, feed the
//! outcome back via `bridge.resolve(id, ..)`, and keep looping until only
//! `Effect::Render` requests remain. Those Render-only bytes are returned to
//! the shell (which just re-reads `pick_view`). The shell therefore never sees
//! a `Pentest` effect — network I/O and auth stay in Rust.
//!
//! This is preferred over the middleware bridge because the async-callback
//! delivery of follow-up effects is a poor fit for a synchronous C ABI (the
//! `EffectResolver` even *panics* if resolved on the calling thread). The
//! synchronous bridge's `EffectFfi` enum is `pub` + `Serialize`/`Deserialize`
//! and carries the operation directly, so routing by effect-kind from outside
//! the core is straightforward.

use std::sync::Arc;

use crux_core::bridge::{Bridge, EffectId, Request};
use crux_core::Core;
use pick_crux_core::{EffectFfi, PickApp};
use pick_crux_middleware::{map_operation, CoreMatrixApi, MatrixApi};

/// Install a `tracing` subscriber once so the core's events (e.g. the gql send
/// error chain) actually surface. iOS writes to stderr (captured by the
/// simulator console / Xcode); Android bridges `tracing` -> `log` -> logcat.
/// Level defaults to `pentest=debug` and honors `RUST_LOG`.
fn init_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        use tracing_subscriber::{prelude::*, EnvFilter};
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("pentest=debug,pick_crux_middleware=debug,info"));

        #[cfg(target_os = "android")]
        {
            android_logger::init_once(
                android_logger::Config::default()
                    .with_max_level(log::LevelFilter::Debug)
                    .with_tag("PickCrux"),
            );
            // Route tracing events into the `log` facade that android_logger drains.
            let _ = tracing_log::LogTracer::init();
            let _ = tracing_subscriber::registry().with(filter).try_init();
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
                .with(filter)
                .try_init();
        }
    });
}


/// Opaque handle owning the bridge, the effect-resolving runtime, and the
/// `MatrixApi` implementation that fulfills `Pentest` effects.
pub struct PickCore {
    bridge: Bridge<PickApp>,
    rt: tokio::runtime::Runtime,
    api: Arc<dyn MatrixApi>,
}

impl PickCore {
    /// Rust-only constructor used by host tests to inject a fake `MatrixApi`.
    /// The extern `pick_core_new` builds the real [`CoreMatrixApi`] and calls
    /// through here. Returns `None` if runtime creation fails.
    pub fn with_api(api: Arc<dyn MatrixApi>) -> Option<Self> {
        let rt = tokio::runtime::Runtime::new().ok()?;
        Some(Self {
            bridge: Bridge::new(Core::<PickApp>::new()),
            rt,
            api,
        })
    }

    /// Serialize the current ViewModel. `None` on serialization failure.
    fn view_bytes(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        self.bridge.view(&mut out).ok()?;
        Some(out)
    }

    /// Feed a bincode `Event`, then run the in-core effect loop. Returns the
    /// serialized `Requests` batch containing only `Render` requests (may be
    /// empty). `None` on any (de)serialization or resolve failure.
    fn update_bytes(&self, event: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        self.bridge.update(event, &mut out).ok()?;
        self.drain_pentest(out)
    }

    /// Resolve a single effect the shell handled (rarely needed under Design A,
    /// kept minimal), then drain any resulting `Pentest` effects in-core.
    fn resolve_bytes(&self, id: EffectId, response: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        self.bridge.resolve(id, response, &mut out).ok()?;
        self.drain_pentest(out)
    }

    /// Repeatedly resolve `Pentest` requests in-core until only `Render`
    /// requests remain; return the serialized Render-only batch.
    /// Bounded by MAX_EFFECT_ITERATIONS to prevent unbounded poll loops from
    /// hanging the FFI call (Task 6 streaming contract is a separate concern).
    fn drain_pentest(&self, first: Vec<u8>) -> Option<Vec<u8>> {
        /// Safety backstop: prevents a non-terminating poll from spinning forever
        /// inside a single `pick_update` call.
        const MAX_EFFECT_ITERATIONS: usize = 1000;

        let mut render_reqs: Vec<Request<EffectFfi>> = Vec::new();
        let mut pending: Vec<Request<EffectFfi>> = bincode::deserialize(&first).ok()?;
        let mut iterations = 0;

        while let Some(req) = pending.pop() {
            iterations += 1;
            if iterations > MAX_EFFECT_ITERATIONS {
                // Cap reached; return whatever Render requests we accumulated.
                break;
            }

            let Request { id, effect } = req;
            match effect {
                EffectFfi::Render(op) => {
                    render_reqs.push(Request {
                        id,
                        effect: EffectFfi::Render(op),
                    });
                }
                EffectFfi::Pentest(op) => {
                    let outcome = self.rt.block_on(map_operation(self.api.as_ref(), op));
                    let outcome_bytes = bincode::serialize(&outcome).ok()?;
                    let mut more = Vec::new();
                    self.bridge.resolve(id, &outcome_bytes, &mut more).ok()?;
                    let more_reqs: Vec<Request<EffectFfi>> = bincode::deserialize(&more).ok()?;
                    pending.extend(more_reqs);
                }
            }
        }

        bincode::serialize(&render_reqs).ok()
    }
}

/// Owned byte buffer handed to the caller. The caller MUST return it via
/// [`pick_buf_free`] exactly once. A null `ptr` with zero `len`/`cap` denotes
/// "no data" (e.g. an error the boundary swallowed).
#[repr(C)]
pub struct PickBuf {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl PickBuf {
    fn empty() -> Self {
        PickBuf {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

/// Transfer ownership of a `Vec<u8>` to the caller as a `PickBuf`.
fn buf_from_vec(v: Option<Vec<u8>>) -> PickBuf {
    match v {
        Some(mut v) => {
            let ptr = v.as_mut_ptr();
            let len = v.len();
            let cap = v.capacity();
            std::mem::forget(v);
            PickBuf { ptr, len, cap }
        }
        None => PickBuf::empty(),
    }
}

/// Build a real [`PickCore`] from a Strike48 API url + auth token.
///
/// The url/token are read as nul-free UTF-8 byte slices. Returns a null pointer
/// if a pointer is null or the bytes are not valid UTF-8.
///
/// # Safety
/// `api_url_ptr`/`token_ptr` must either be null or point to at least
/// `api_url_len`/`token_len` initialized bytes.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // FFI entrypoint; pointers are null-checked and read via from_raw_parts.
pub extern "C" fn pick_core_new(
    api_url_ptr: *const u8,
    api_url_len: usize,
    token_ptr: *const u8,
    token_len: usize,
) -> *mut PickCore {
    let read = |ptr: *const u8, len: usize| -> Option<String> {
        if ptr.is_null() {
            // An empty (zero-length) input is legitimate; a null pointer is not.
            return if len == 0 { Some(String::new()) } else { None };
        }
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        std::str::from_utf8(slice).ok().map(str::to_owned)
    };

    init_tracing();

    let (Some(api_url), Some(token)) = (read(api_url_ptr, api_url_len), read(token_ptr, token_len))
    else {
        return std::ptr::null_mut();
    };

    // Dev-only: trust the local cluster's mkcert-signed TLS so debug builds can
    // reach https://*.strike48.test. reqwest here uses rustls-tls-native-roots,
    // and rustls-native-certs does not reliably read the iOS simulator trust
    // store (adding the CA via `simctl keychain add-root-cert` isn't picked up),
    // so we relax verification instead. Release builds (debug_assertions off)
    // keep strict TLS — this never ships. The proper prod path is bundling the
    // CA or webpki roots + a real cert. The matrix client reads this env when it
    // builds its client.
    #[cfg(debug_assertions)]
    if std::env::var_os("MATRIX_TLS_INSECURE").is_none() {
        std::env::set_var("MATRIX_TLS_INSECURE", "true");
    }

    let api: Arc<dyn MatrixApi> = Arc::new(CoreMatrixApi::new(api_url, token, None));
    match PickCore::with_api(api) {
        Some(core) => Box::into_raw(Box::new(core)),
        None => std::ptr::null_mut(),
    }
}

/// Adopt an auth token the shell obtained via native OAuth (the `__st` Studio
/// session token). All subsequent core calls use it. No-op on a null handle or
/// non-UTF-8 bytes. The shell should call `pick_view`/`pick_update` afterwards
/// to re-drive with the new credential.
///
/// # Safety
/// `core` must be a pointer from `pick_core_new` (or null); `token_ptr` must be
/// null or point to at least `token_len` initialized bytes.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // FFI entrypoint; pointers are null-checked.
pub extern "C" fn pick_set_token(core: *mut PickCore, token_ptr: *const u8, token_len: usize) {
    let Some(core) = (unsafe { core.as_ref() }) else {
        return;
    };
    if token_ptr.is_null() {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(token_ptr, token_len) };
    if let Ok(token) = std::str::from_utf8(slice) {
        core.api.set_token(token.to_owned());
        // The shell authenticated out-of-band (native OAuth), so the in-core
        // SignIn effect never ran. Drive the model to Connected by feeding a
        // successful SignInResult, so the ViewModel's connection phase/label
        // reflect the adopted token (otherwise it stays "Connecting...").
        let event = pick_crux_core::Event::SignInResult(pick_crux_core::SignInOutcome {
            token: Some(token.to_owned()),
            error: None,
        });
        if let Ok(bytes) = bincode::serialize(&event) {
            let _ = core.update_bytes(&bytes);
        }
    }
}

/// Free a [`PickCore`] previously returned by `pick_core_new`.
///
/// # Safety
/// `core` must be a pointer returned by `pick_core_new` (or null) and must not
/// be used again after this call.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // FFI entrypoint; pointer is null-checked before reclaim.
pub extern "C" fn pick_core_free(core: *mut PickCore) {
    if core.is_null() {
        return;
    }
    drop(unsafe { Box::from_raw(core) });
}

/// Free a [`PickBuf`] previously returned by this library.
///
/// # Safety
/// `buf` must have been produced by this library and freed exactly once. A null
/// `ptr` is a no-op.
#[no_mangle]
pub extern "C" fn pick_buf_free(buf: PickBuf) {
    if buf.ptr.is_null() {
        return;
    }
    drop(unsafe { Vec::from_raw_parts(buf.ptr, buf.len, buf.cap) });
}

/// Serialized ViewModel bytes for the current core state. Empty buffer on a
/// null handle or serialization failure.
///
/// # Safety
/// `core` must be null or a valid pointer from `pick_core_new`.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // FFI entrypoint; handle is null-checked before use.
pub extern "C" fn pick_view(core: *mut PickCore) -> PickBuf {
    let Some(core) = (unsafe { core.as_ref() }) else {
        return PickBuf::empty();
    };
    buf_from_vec(core.view_bytes())
}

/// Feed a bincode `Event`, run the in-core Pentest resolution loop, and return
/// the remaining (Render-only) request bytes. Empty buffer on a null handle,
/// null event, or any failure.
///
/// # Safety
/// `core` must be null or valid; `event_ptr` must be null or point to
/// `event_len` initialized bytes.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // FFI entrypoint; pointers are null-checked and read via from_raw_parts.
pub extern "C" fn pick_update(
    core: *mut PickCore,
    event_ptr: *const u8,
    event_len: usize,
) -> PickBuf {
    let Some(core) = (unsafe { core.as_ref() }) else {
        return PickBuf::empty();
    };
    if event_ptr.is_null() {
        return PickBuf::empty();
    }
    let event = unsafe { std::slice::from_raw_parts(event_ptr, event_len) };
    buf_from_vec(core.update_bytes(event))
}

/// Resolve a shell-handled effect by its `EffectId` (a bincode-agnostic `u32`),
/// then drain any resulting Pentest effects in-core. Kept minimal for Task 1;
/// under Design A the shell should not normally need this.
///
/// # Safety
/// `core` must be null or valid; `resp_ptr` must be null or point to
/// `resp_len` initialized bytes.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // FFI entrypoint; pointers are null-checked and read via from_raw_parts.
pub extern "C" fn pick_resolve(
    core: *mut PickCore,
    effect_id: u32,
    resp_ptr: *const u8,
    resp_len: usize,
) -> PickBuf {
    let Some(core) = (unsafe { core.as_ref() }) else {
        return PickBuf::empty();
    };
    if resp_ptr.is_null() {
        return PickBuf::empty();
    }
    let resp = unsafe { std::slice::from_raw_parts(resp_ptr, resp_len) };
    buf_from_vec(core.resolve_bytes(EffectId(effect_id), resp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pick_crux_core::effect::ConversationDelta;
    use pick_crux_core::view::{ConversationRef, DocRef, MessageView};
    use pick_crux_core::{Event, ViewModel};

    /// Fake MatrixApi mirroring the crux-middleware test double: `send`
    /// returns a conversation id, `poll` returns a done delta immediately.
    struct FakeApi;

    #[async_trait::async_trait]
    impl MatrixApi for FakeApi {
        async fn send(&self, _c: Option<String>, _t: String) -> Result<String, String> {
            Ok("conv-x".into())
        }
        async fn poll(&self, _c: String) -> Result<ConversationDelta, String> {
            Ok(ConversationDelta {
                messages: vec![],
                tool_calls: vec![],
                done: true,
            })
        }
        async fn list_documents(&self, _a: Option<String>) -> Result<Vec<DocRef>, String> {
            Ok(vec![])
        }
        async fn sign_in(&self, _u: String) -> Result<String, String> {
            Ok("tok".into())
        }
        async fn doc_content(&self, _id: String, _c: String) -> Result<String, String> {
            Ok("# report".into())
        }
        async fn shared_link(&self, _c: String, _d: String) -> Result<String, String> {
            Ok("https://s/x".into())
        }
        async fn list_conversations(&self) -> Result<Vec<ConversationRef>, String> {
            Ok(vec![])
        }
        async fn load_conversation(&self, _c: String) -> Result<Vec<MessageView>, String> {
            Ok(vec![])
        }
    }

    fn fake_core() -> *mut PickCore {
        Box::into_raw(Box::new(PickCore::with_api(Arc::new(FakeApi)).expect("test runtime")))
    }

    #[test]
    fn view_round_trips() {
        let core = fake_core();
        let buf = pick_view(core);
        assert!(!buf.ptr.is_null(), "view produced bytes");
        let bytes = unsafe { std::slice::from_raw_parts(buf.ptr, buf.len) };
        let vm: ViewModel = bincode::deserialize(bytes).expect("decode ViewModel");
        assert!(vm.show_scan_card, "fresh core shows the scan card");
        assert!(!vm.scan_in_progress);
        pick_buf_free(buf);
        pick_core_free(core);
    }

    #[test]
    fn set_token_marks_connected() {
        use pick_crux_core::view::ConnectionPhase;
        let core = fake_core();

        // Fresh core is Connecting (default phase), not yet Connected.
        let vm0: ViewModel = {
            let b = pick_view(core);
            let v = bincode::deserialize(unsafe {
                std::slice::from_raw_parts(b.ptr, b.len)
            })
            .unwrap();
            pick_buf_free(b);
            v
        };
        assert_eq!(vm0.connection.phase, ConnectionPhase::Connecting);

        // Adopting a shell-obtained token drives the model to Connected so the
        // UI leaves "Connecting..." even though the in-core SignIn never ran.
        let token = b"shell-oauth-token";
        pick_set_token(core, token.as_ptr(), token.len());

        let vm1: ViewModel = {
            let b = pick_view(core);
            let v = bincode::deserialize(unsafe {
                std::slice::from_raw_parts(b.ptr, b.len)
            })
            .unwrap();
            pick_buf_free(b);
            v
        };
        assert_eq!(vm1.connection.phase, ConnectionPhase::Connected);
        assert!(!vm1.needs_sign_in);
        pick_core_free(core);
    }

    #[test]
    fn start_scan_resolves_in_core() {
        let core = fake_core();

        // Fresh core shows the scan card.
        let v0 = pick_view(core);
        let vm0: ViewModel =
            bincode::deserialize(unsafe { std::slice::from_raw_parts(v0.ptr, v0.len) }).unwrap();
        assert!(vm0.show_scan_card);
        pick_buf_free(v0);

        // Feed StartScan; the in-core loop must resolve the whole Pentest chain
        // (SendScan -> Poll -> ListDocuments) via the fake api, ending in Render.
        let event = bincode::serialize(&Event::StartScan).expect("serialize event");
        let reqs = pick_update(core, event.as_ptr(), event.len());
        // A Render-only batch (possibly empty) comes back; never a Pentest one.
        let req_bytes = if reqs.ptr.is_null() {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(reqs.ptr, reqs.len) }.to_vec()
        };
        let remaining: Vec<Request<EffectFfi>> = bincode::deserialize(&req_bytes).unwrap();
        assert!(
            remaining
                .iter()
                .all(|r| matches!(r.effect, EffectFfi::Render(_))),
            "no Pentest effects should reach the shell"
        );
        pick_buf_free(reqs);

        // The view now reflects a started scan: conversation_id is set, so the
        // scan card is gone and the scan is no longer in progress (done delta).
        let v1 = pick_view(core);
        let vm1: ViewModel =
            bincode::deserialize(unsafe { std::slice::from_raw_parts(v1.ptr, v1.len) }).unwrap();
        assert!(
            !vm1.show_scan_card,
            "scan card hidden once the in-core loop set the conversation id"
        );
        assert!(!vm1.scan_in_progress, "done delta ends the scan in-core");
        pick_buf_free(v1);

        pick_core_free(core);
    }

    #[test]
    fn buffer_free_is_sound() {
        // Allocate and free without leak/double-free. (miri not run here; this
        // is a basic soundness check of the alloc/forget/reclaim round-trip.)
        let buf = buf_from_vec(Some(vec![1u8, 2, 3, 4]));
        assert_eq!(buf.len, 4);
        assert!(!buf.ptr.is_null());
        pick_buf_free(buf);

        // Empty buffer free is a no-op and must not crash.
        pick_buf_free(PickBuf::empty());

        // A null handle yields an empty buffer, freed safely.
        let empty = pick_view(std::ptr::null_mut());
        assert!(empty.ptr.is_null());
        pick_buf_free(empty);
    }
}
