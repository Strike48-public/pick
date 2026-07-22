#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Opaque handle owning the middleware bridge, the effect-resolving runtime,
 * and the `MatrixApi` the middleware fulfills `Pentest` effects with.
 */
typedef struct PickCore PickCore;

/**
 * A C callback the shell registers to be pinged whenever the view may have
 * changed (an async effect resolved). The shell responds by calling
 * `pick_view` on its side and re-rendering. `user_data` is passed back
 * verbatim. Must be `Send`-safe: it is invoked from the middleware's
 * background thread.
 */
typedef void (*NotifyFn)(void *user_data);

/**
 * Owned byte buffer handed to the caller. The caller MUST return it via
 * [`pick_buf_free`] exactly once. A null `ptr` with zero `len`/`cap` denotes
 * "no data" (e.g. an error the boundary swallowed).
 */
typedef struct PickBuf {
  uint8_t *ptr;
  uintptr_t len;
  uintptr_t cap;
} PickBuf;

/**
 * Build a real [`PickCore`] from a Strike48 API url + auth token.
 *
 * `notify` is called (with `user_data`) whenever an async effect resolves and
 * the view may have changed; the shell responds by calling `pick_view` and
 * re-rendering. `notify` may be invoked from a background thread, so the shell
 * must hop to its UI thread. `user_data` must outlive the core.
 *
 * The url/token are read as nul-free UTF-8 byte slices. Returns a null pointer
 * if a required pointer is null or the bytes are not valid UTF-8.
 *
 * # Safety
 * `api_url_ptr`/`token_ptr` must be null or point to at least the given number
 * of initialized bytes. `notify` must be a valid function pointer.
 */
struct PickCore *pick_core_new(const uint8_t *api_url_ptr,
                               uintptr_t api_url_len,
                               const uint8_t *token_ptr,
                               uintptr_t token_len,
                               NotifyFn notify,
                               void *user_data);

/**
 * Update the notify callback + user-data after construction.
 *
 * Shells whose object model can't produce a stable `self` pointer until after
 * init (e.g. Swift classes) pass a null `user_data` to `pick_core_new`, then
 * call this once fully constructed. No-op on a null handle.
 *
 * # Safety
 * `core` must be a pointer from `pick_core_new` (or null). `notify` must be a
 * valid function pointer; `user_data` must outlive the core.
 */
void pick_set_notify(struct PickCore *core, NotifyFn notify, void *user_data);

/**
 * Adopt an auth token the shell obtained via native OAuth (the `__st` Studio
 * session token). All subsequent core calls use it. No-op on a null handle or
 * non-UTF-8 bytes. The shell should call `pick_view`/`pick_update` afterwards
 * to re-drive with the new credential.
 *
 * # Safety
 * `core` must be a pointer from `pick_core_new` (or null); `token_ptr` must be
 * null or point to at least `token_len` initialized bytes.
 */
void pick_set_token(struct PickCore *core, const uint8_t *token_ptr, uintptr_t token_len);

/**
 * Free a [`PickCore`] previously returned by `pick_core_new`.
 *
 * # Safety
 * `core` must be a pointer returned by `pick_core_new` (or null) and must not
 * be used again after this call.
 */
void pick_core_free(struct PickCore *core);

/**
 * Free a [`PickBuf`] previously returned by this library.
 *
 * # Safety
 * `buf` must have been produced by this library and freed exactly once. A null
 * `ptr` is a no-op.
 */
void pick_buf_free(struct PickBuf buf);

/**
 * Serialized ViewModel bytes for the current core state. Empty buffer on a
 * null handle or serialization failure.
 *
 * # Safety
 * `core` must be null or a valid pointer from `pick_core_new`.
 */
struct PickBuf pick_view(struct PickCore *core);

/**
 * Feed a bincode `Event`, run the in-core Pentest resolution loop, and return
 * the remaining (Render-only) request bytes. Empty buffer on a null handle,
 * null event, or any failure.
 *
 * # Safety
 * `core` must be null or valid; `event_ptr` must be null or point to
 * `event_len` initialized bytes.
 */
struct PickBuf pick_update(struct PickCore *core, const uint8_t *event_ptr, uintptr_t event_len);
