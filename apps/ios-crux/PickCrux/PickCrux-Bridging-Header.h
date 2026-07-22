// Bridging header exposing the crux FFI C ABI to Swift.
// The header lives in crates/crux-ffi/include and is reached via
// HEADER_SEARCH_PATHS in the Xcode build settings.
#include "pick_crux_ffi.h"
