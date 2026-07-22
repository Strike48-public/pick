#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Opaque handle owning the bridge, the effect-resolving runtime, and the
 * `MatrixApi` implementation that fulfills `Pentest` effects.
 */
typedef struct PickCore PickCore;

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
 * The url/token are read as nul-free UTF-8 byte slices. Returns a null pointer
 * if a pointer is null or the bytes are not valid UTF-8.
 *
 * # Safety
 * `api_url_ptr`/`token_ptr` must either be null or point to at least
 * `api_url_len`/`token_len` initialized bytes.
 */
struct PickCore *pick_core_new(const uint8_t *api_url_ptr,
                               uintptr_t api_url_len,
                               const uint8_t *token_ptr,
                               uintptr_t token_len);

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

/**
 * Resolve a shell-handled effect by its `EffectId` (a bincode-agnostic `u32`),
 * then drain any resulting Pentest effects in-core. Kept minimal for Task 1;
 * under Design A the shell should not normally need this.
 *
 * # Safety
 * `core` must be null or valid; `resp_ptr` must be null or point to
 * `resp_len` initialized bytes.
 */
struct PickBuf pick_resolve(struct PickCore *core,
                            uint32_t effect_id,
                            const uint8_t *resp_ptr,
                            uintptr_t resp_len);
