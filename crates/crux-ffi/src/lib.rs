//! Stable C ABI over the crux **middleware** `Bridge` — push-based, non-blocking.
//!
//! # Effect routing (middleware bridge, async)
//!
//! We wrap `Core<PickApp>` with the [`PentestMiddleware`] via
//! [`Layer::handle_effects_using`], then terminate the stack with
//! [`Layer::bridge`], which yields a [`crux_core::middleware::Bridge`]. The
//! middleware resolves every `Effect::Pentest(op)` **asynchronously on a
//! background tokio thread** (see [`PentestMiddleware::try_process_effect`]);
//! `Effect::Render` stays inside the bridge (it tracks the latest view model).
//!
//! Flow:
//!  * `pick_update(event)` calls `bridge.update(..)` and returns **immediately**
//!    — it never blocks on network I/O. The middleware spawns the `Pentest`
//!    work off-thread.
//!  * When an effect resolves (including each `PollConversation` the App
//!    re-emits while streaming a conversation), the bridge invokes the
//!    construction-time `effect_callback`. We forward that as a single
//!    `notify()` ping across the C ABI so the shell re-reads `pick_view` and
//!    re-renders. This is the streaming path — driven by the App re-emitting
//!    poll effects, not a shell-side timer or a synchronous drain loop.
//!
//! The shell therefore never sees a `Pentest` effect (network I/O and auth stay
//! in Rust), the UI thread is never blocked, and a scan streams incrementally.

use std::os::raw::c_void;
use std::sync::Arc;

use crux_core::middleware::{Bridge, Layer};
use crux_core::Core;
use pick_crux_core::PickApp;
use pick_crux_middleware::{CoreMatrixApi, MatrixApi, PentestMiddleware};

/// The concrete middleware-wrapped layer the bridge sits on:
/// `Core<PickApp>` with `PentestMiddleware` handling `Pentest` effects.
type PickLayer =
    crux_core::middleware::HandleEffectLayer<Core<PickApp>, PentestMiddleware>;
type PickBridge = Bridge<PickLayer, crux_core::bridge::BincodeFfiFormat>;

/// A C callback the shell registers to be pinged whenever the view may have
/// changed (an async effect resolved). The shell responds by calling
/// `pick_view` on its side and re-rendering. `user_data` is passed back
/// verbatim. Must be `Send`-safe: it is invoked from the middleware's
/// background thread.
pub type NotifyFn = extern "C" fn(user_data: *mut c_void);

/// Wraps the shell callback + its opaque user-data so it can cross threads.
/// Safety: the shell guarantees `user_data` outlives the core and that
/// `notify` is safe to call from any thread (the shell hops to its UI thread).
struct ShellNotifier {
    notify: NotifyFn,
    user_data: *mut c_void,
}
// SAFETY: the pointer is only ever passed back to the shell-provided `notify`;
// we never dereference it in Rust. The shell owns its thread-safety.
unsafe impl Send for ShellNotifier {}
unsafe impl Sync for ShellNotifier {}

impl ShellNotifier {
    fn ping(&self) {
        (self.notify)(self.user_data);
    }
}

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
        #[cfg(target_os = "ios")]
        {
            // stderr from a sim app is not captured by the unified log, so route
            // to os_log (visible in Console.app / `xcrun simctl spawn booted log`).
            let _ = tracing_subscriber::registry()
                .with(tracing_oslog::OsLogger::new(
                    "com.strike48.pickcrux",
                    "core",
                ))
                .with(filter)
                .try_init();
        }
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        {
            let _ = tracing_subscriber::registry()
                .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
                .with(filter)
                .try_init();
        }
    });
}


/// Opaque handle owning the middleware bridge, the effect-resolving runtime,
/// and the `MatrixApi` the middleware fulfills `Pentest` effects with.
pub struct PickCore {
    bridge: PickBridge,
    /// Kept alive for the core's lifetime: the middleware spawns onto it.
    _rt: tokio::runtime::Runtime,
    /// Shared with `PentestMiddleware` so the shell can swap the auth token.
    api: Arc<dyn MatrixApi>,
}

impl PickCore {
    /// Build a core over `api`, pinging `notifier` whenever an async effect
    /// resolves (so the shell re-reads the view). Returns `None` if the tokio
    /// runtime can't be created.
    fn build(api: Arc<dyn MatrixApi>, notifier: ShellNotifier) -> Option<Self> {
        let rt = tokio::runtime::Runtime::new().ok()?;
        let middleware = PentestMiddleware::new(rt.handle().clone(), api.clone());

        // The bridge invokes this callback when effects resolve out-of-band
        // (on the middleware's background thread). We don't need the request
        // bytes here — the shell re-reads `pick_view` — so any Ok/Err just
        // pings the shell to refresh. This is the streaming signal.
        let bridge = Core::<PickApp>::new()
            .handle_effects_using(middleware)
            .bridge::<crux_core::bridge::BincodeFfiFormat>(move |_result| {
                notifier.ping();
            });

        Some(Self {
            bridge,
            _rt: rt,
            api,
        })
    }

    /// Serialize the current ViewModel. `None` on serialization failure.
    fn view_bytes(&self) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        self.bridge.view(&mut out).ok()?;
        Some(out)
    }

    /// Feed a bincode `Event`. Returns immediately; `Pentest` effects resolve
    /// asynchronously and ping the shell via the notifier as they complete.
    /// The returned request bytes (Render-only, produced synchronously) are
    /// ignored by the shell, which re-reads `pick_view`.
    fn update_bytes(&self, event: &[u8]) -> Option<Vec<u8>> {
        let mut out = Vec::new();
        self.bridge.update(event, &mut out).ok()?;
        Some(out)
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
/// `notify` is called (with `user_data`) whenever an async effect resolves and
/// the view may have changed; the shell responds by calling `pick_view` and
/// re-rendering. `notify` may be invoked from a background thread, so the shell
/// must hop to its UI thread. `user_data` must outlive the core.
///
/// The url/token are read as nul-free UTF-8 byte slices. Returns a null pointer
/// if a required pointer is null or the bytes are not valid UTF-8.
///
/// # Safety
/// `api_url_ptr`/`token_ptr` must be null or point to at least the given number
/// of initialized bytes. `notify` must be a valid function pointer.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)] // FFI entrypoint; pointers are null-checked and read via from_raw_parts.
pub extern "C" fn pick_core_new(
    api_url_ptr: *const u8,
    api_url_len: usize,
    token_ptr: *const u8,
    token_len: usize,
    notify: NotifyFn,
    user_data: *mut c_void,
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

    // Dev-only: trust the local cluster's mkcert-signed TLS so dev builds can
    // reach https://*.strike48.test. The server sends only the leaf cert (no
    // intermediate), so the sim's trust evaluation fails with MissingIntermediate;
    // reqwest here uses rustls-tls-native-roots which can't build the chain
    // either. Gated behind the `insecure-tls` cargo feature (NOT debug_assertions,
    // which is off for the release-ffi profile the mobile libs build with) so it
    // is impossible to ship by accident. The proper prod path is a real cert /
    // full chain. The matrix client reads this env when it builds its client.
    #[cfg(feature = "insecure-tls")]
    if std::env::var_os("MATRIX_TLS_INSECURE").is_none() {
        std::env::set_var("MATRIX_TLS_INSECURE", "true");
    }

    let api: Arc<dyn MatrixApi> = Arc::new(CoreMatrixApi::new(api_url, token, None));
    let notifier = ShellNotifier { notify, user_data };
    match PickCore::build(api, notifier) {
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

// Note: there is no `pick_resolve` under the middleware-bridge design. All
// `Pentest` effects resolve inside the core (on the middleware's background
// thread); the shell only feeds events (`pick_update`), adopts tokens
// (`pick_set_token`), and reads the view (`pick_view`). Render effects are
// handled by the bridge itself.

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

    /// A ping counter the notifier increments, so tests can wait for async
    /// effect resolution instead of sleeping blindly.
    static PING_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    extern "C" fn counting_notify(_user_data: *mut c_void) {
        PING_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn fake_core() -> *mut PickCore {
        PING_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
        let notifier = ShellNotifier {
            notify: counting_notify,
            user_data: std::ptr::null_mut(),
        };
        Box::into_raw(Box::new(
            PickCore::build(Arc::new(FakeApi), notifier).expect("test runtime"),
        ))
    }

    /// Decode the current view of `core`.
    fn view_of(core: *mut PickCore) -> ViewModel {
        let b = pick_view(core);
        let v = bincode::deserialize(unsafe { std::slice::from_raw_parts(b.ptr, b.len) })
            .expect("decode ViewModel");
        pick_buf_free(b);
        v
    }

    /// Poll the view until `pred` holds or the deadline passes. Async effects
    /// resolve on the middleware's background thread, so tests wait on the
    /// resulting state rather than assuming synchronous completion.
    fn wait_for(core: *mut PickCore, pred: impl Fn(&ViewModel) -> bool) -> ViewModel {
        for _ in 0..200 {
            let vm = view_of(core);
            if pred(&vm) {
                return vm;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("condition not met within timeout");
    }

    #[test]
    fn view_round_trips() {
        let core = fake_core();
        let vm = view_of(core);
        assert!(vm.show_scan_card, "fresh core shows the scan card");
        assert!(!vm.scan_in_progress);
        pick_core_free(core);
    }

    #[test]
    fn set_token_marks_connected() {
        use pick_crux_core::view::ConnectionPhase;
        let core = fake_core();

        // Fresh core is Connecting (default phase), not yet Connected.
        assert_eq!(view_of(core).connection.phase, ConnectionPhase::Connecting);

        // Adopting a shell-obtained token drives the model to Connected so the
        // UI leaves "Connecting..." even though the in-core SignIn never ran.
        let token = b"shell-oauth-token";
        pick_set_token(core, token.as_ptr(), token.len());

        let vm1 = view_of(core);
        assert_eq!(vm1.connection.phase, ConnectionPhase::Connected);
        assert!(!vm1.needs_sign_in);
        pick_core_free(core);
    }

    #[test]
    fn start_scan_streams_and_notifies() {
        let core = fake_core();
        assert!(view_of(core).show_scan_card, "fresh core shows the scan card");

        // Feed StartScan; pick_update returns IMMEDIATELY (non-blocking). The
        // Pentest chain (SendScan -> Poll -> ListDocuments) resolves on the
        // middleware's background thread and pings the notifier as it goes.
        let event = bincode::serialize(&Event::StartScan).expect("serialize event");
        let reqs = pick_update(core, event.as_ptr(), event.len());
        pick_buf_free(reqs);

        // Eventually the async resolution advances the view: the conversation id
        // is set so the scan card is gone, and the done delta ends the scan.
        let vm = wait_for(core, |vm| !vm.show_scan_card && !vm.scan_in_progress);
        assert!(!vm.show_scan_card);
        assert!(!vm.scan_in_progress);

        // The notifier must have fired at least once (the streaming signal that
        // tells the shell to re-read the view) — proving push, not poll.
        assert!(
            PING_COUNT.load(std::sync::atomic::Ordering::SeqCst) > 0,
            "effect resolution should have pinged the shell notifier"
        );
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
