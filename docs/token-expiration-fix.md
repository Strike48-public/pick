# Automatic JWT Token Expiration Handling

## Problem

Pick was experiencing registration failures due to expired JWT tokens:

```
ERROR pentest_ui::liveview_connector: Registration failed: Registration failed
```

**Root cause:**
1. JWT tokens expire after 5 minutes
2. Pick saves tokens to `~/.config/pentest-connector/settings.json`
3. On restart, Pick tries to reuse the expired token
4. Server rejects the expired token

## Solution

Implemented automatic token validation and cleanup on startup.

### What Was Added

**New module:** `crates/core/src/jwt_validator.rs`

Key functions:
- `is_jwt_expired(token)` - Check if a JWT is expired (with 30s buffer)
- `validate_token(token)` - Validate and clear expired tokens

**Updated:** `crates/core/src/settings.rs`

The `load_settings()` function now:
1. Loads settings from disk
2. Validates the JWT token expiration
3. Automatically clears expired tokens
4. Saves the updated settings back to disk

### How It Works

```rust
// When loading settings
let mut settings = load_settings_from_disk();

// Validate JWT token
if let Some(validated) = jwt_validator::validate_token(&token) {
    // Token is valid, keep it
    settings.auth_token = validated;
} else {
    // Token is expired or invalid, clear it
    settings.auth_token.clear();
    save_settings(&settings); // Persist the change
}
```

### Benefits

✅ **No manual intervention** - Expired tokens are cleared automatically
✅ **Fallback to OTT** - Pick uses environment OTT when token is cleared
✅ **Clock skew tolerance** - 30 second buffer prevents edge cases
✅ **Logged** - Token clearing is logged for debugging

### Testing

1. **Expired token test:**
   ```bash
   # Token in settings.json is expired
   cargo run --bin pentest-agent
   # Should see: "Cleared expired/invalid auth token from settings"
   # Pick will re-register using OTT from .env
   ```

2. **Valid token test:**
   ```bash
   # Token is still valid (< 5 minutes old)
   cargo run --bin pentest-agent
   # Should connect successfully using the saved token
   ```

3. **Invalid token test:**
   ```bash
   # Manually corrupt the token in settings.json
   # Pick will detect invalid format and clear it
   ```

## User Experience

**Before:** Registration failed every restart, user had to manually edit settings.json

**After:** Registration succeeds automatically - Pick handles token lifecycle transparently

## Future Improvements

Potential enhancements (not implemented):

1. **Token refresh** - Automatically refresh tokens before expiration
2. **Don't persist tokens** - Always use OTT flow from environment
3. **Refresh token support** - Use OAuth2 refresh tokens for long-lived sessions
4. **Better error messages** - Show why registration failed (expired, invalid, network)

## Implementation Details

### JWT Structure

```
header.payload.signature
```

We parse the `payload` (base64-encoded JSON) to extract:
- `exp` - Expiration timestamp (Unix epoch)
- `iat` - Issued-at timestamp (optional)

### Expiration Check

```rust
let now = current_timestamp();
let expired = token.exp < now + 30; // 30 second buffer
```

The 30-second buffer handles:
- Clock skew between client and server
- Network delays during registration
- Edge cases at the exact expiration moment

### Security Considerations

✅ We don't validate signatures (not needed for expiration check)
✅ We don't expose token contents in logs
✅ We handle malformed tokens gracefully
✅ We use constant-time operations (no timing attacks)

## Code Locations

- **JWT Validator:** `crates/core/src/jwt_validator.rs`
- **Settings Loader:** `crates/core/src/settings.rs` (line 30-56)
- **Module Export:** `crates/core/src/lib.rs` (line 9)

## Related Issues

This fix resolves the recurring "Registration failed" errors that required manual intervention to clear expired tokens from settings.json.
