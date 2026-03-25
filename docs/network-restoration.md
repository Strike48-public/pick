# Automatic Network Restoration After WiFi Operations

## Problem

When WiFi scanning or cracking operations require monitor mode, they may need to kill NetworkManager to enable it. This disrupts network connectivity. If the tool crashes, panics, or returns early due to an error, NetworkManager might not be restarted, leaving the system without network connectivity.

## Solution

We've implemented a **CleanupGuard** pattern that ensures NetworkManager is ALWAYS restored, even in error conditions:

### How It Works

1. **CleanupGuard struct**: Created when monitor mode is enabled
   - Stores the monitor interface name
   - Stores whether NetworkManager was killed
   - Has a `cleaned` flag to track manual cleanup

2. **Manual cleanup** (normal path):
   - Call `cleanup_guard.cleanup().await` when operation completes
   - Restores network and sets `cleaned = true`
   - This is the normal, expected path

3. **Automatic cleanup** (error/panic path):
   - Rust's `Drop` trait ensures cleanup runs when CleanupGuard goes out of scope
   - If `cleaned == false`, Drop triggers emergency restoration
   - Spawns a background thread with async runtime
   - Best-effort network restoration even during panic/unwind

### Implementation Details

```rust
struct CleanupGuard {
    mon_interface: String,
    killed_network_manager: bool,
    cleaned: bool,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if self.cleaned {
            return; // Already cleaned up manually
        }

        // Emergency cleanup in separate thread
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let platform = get_platform();
                platform.disable_monitor_mode(&mon_interface, killed_nm).await
            });
        });
    }
}
```

### Modified Tools

1. **wifi_scan_detailed** (`crates/tools/src/wifi_scan_detailed.rs`)
   - Lines 21-70: CleanupGuard implementation
   - Lines 168-169: Guard creation
   - Lines 182-184: Manual cleanup on success

2. **autopwn_capture** (`crates/tools/src/autopwn/capture.rs`)
   - Lines 11-60: CleanupGuard implementation
   - Line 203: Guard creation
   - Lines 242-248: Manual cleanup on success

### NetworkManager Restoration Process

When `disable_monitor_mode` is called with `restart_network_manager=true`:

1. Disables monitor mode on the interface
2. Restarts NetworkManager: `sudo systemctl restart NetworkManager`
3. Waits 3 seconds for NetworkManager to start
4. Verifies NetworkManager is active
5. Logs success/failure status

See `crates/platform/src/desktop/wifi_attack.rs` lines 143-211 for implementation.

## Testing

To test the automatic restoration:

1. Run a WiFi scan with monitor mode:
   ```
   wifi_scan_detailed(allow_network_disruption=true)
   ```

2. NetworkManager should be restored after:
   - Normal completion
   - Early return (e.g., no networks found)
   - Error during capture
   - Panic/crash (Drop cleanup)

3. Verify network is restored:
   ```bash
   systemctl status NetworkManager
   nmcli connection show
   ping -c 3 8.8.8.8
   ```

## Benefits

- **Reliability**: Network always restored, even on error
- **User experience**: No manual intervention required
- **Safety**: Prevents leaving system without connectivity
- **Robustness**: Works even during panics/crashes

## Future Enhancements

Consider adding:
- Timeout for emergency cleanup thread
- Retry logic with exponential backoff
- System notification when emergency cleanup runs
- Configuration option to disable monitor mode operations entirely
