//! Locally observed scan durations, used to ground the "how long will this
//! take?" UX copy in real run times instead of a hardcoded guess that rots.
//!
//! Each completed Easy Mode scan records how long it took (wall clock from the
//! scan button press to the report document appearing). The rolling window of
//! recent durations is stored in its own small JSON file — deliberately NOT in
//! `settings.json`, so a detached write here can never be clobbered by the
//! signal-based `AppSettings` save path (the same failure mode as #373).
//!
//! No PII or target data: only integer durations, capped at the last
//! [`MAX_ENTRIES`] entries.

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::settings::settings_dir;

/// Keep at most this many recent scan durations.
const MAX_ENTRIES: usize = 10;
/// Minimum completed scans before the estimate gets specific (a single
/// observation is not a pattern — see `typical_label_from`).
const MIN_OBSERVATIONS: usize = 2;
/// Ignore measurements outside this plausible window: a "scan" that finishes in
/// under a half-minute almost certainly never really scanned, and anything over
/// an hour is a wedged run, not a data point.
const MIN_SECS: u64 = 30;
const MAX_SECS: u64 = 3600;

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct ScanStatsFile {
    durations_secs: Vec<u64>,
}

fn file_path() -> std::path::PathBuf {
    // Test/dev seam: a controlled path so the record/read wiring through
    // `file_path()` itself can be exercised without touching the user's real
    // config dir (the roundtrip test otherwise bypasses it with temp paths —
    // review nit on pick#610).
    if let Ok(p) = std::env::var("PICK_SCAN_STATS_FILE") {
        return std::path::PathBuf::from(p);
    }
    settings_dir().join("scan_stats.json")
}

fn load_from(path: &Path) -> ScanStatsFile {
    match fs::read_to_string(path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => ScanStatsFile::default(),
    }
}

fn save_to(path: &Path, stats: &ScanStatsFile) -> anyhow::Result<()> {
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_string_pretty(stats)?)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Merge one completed scan's wall-clock duration into a history. Out-of-range
/// measurements are dropped so a wedged or no-op run can't skew the estimate,
/// and the window is capped to the newest [`MAX_ENTRIES`] entries.
fn merge_entry(durations: &mut Vec<u64>, secs: u64) {
    if !(MIN_SECS..=MAX_SECS).contains(&secs) {
        return;
    }
    durations.push(secs);
    if durations.len() > MAX_ENTRIES {
        durations.drain(0..durations.len() - MAX_ENTRIES);
    }
}

/// Record one completed scan's wall-clock duration (see [`merge_entry`] for the
/// sanity rules).
pub fn record_scan_duration(secs: u64) {
    let path = file_path();
    let mut stats = load_from(&path);
    merge_entry(&mut stats.durations_secs, secs);
    if let Err(e) = save_to(&path, &stats) {
        tracing::warn!("Failed to save scan duration stats: {e}");
    } else {
        // Invalidate the memoized label (see `typical_scan_duration_label`).
        STATS_GENERATION.fetch_add(1, Ordering::Relaxed);
    }
}

/// Recent completed-scan durations, oldest first (empty on a fresh install).
pub fn recent_scan_durations() -> Vec<u64> {
    load_from(&file_path()).durations_secs
}

/// Lower median of a duration history — robust to one slow or one fast
/// outlier, and biased toward the shorter side so a typical run does not
/// overshoot the stated expectation. `None` on an empty history.
fn typical_secs_from(durations: &[u64]) -> Option<u64> {
    let mut v = durations.to_vec();
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    Some(v[(v.len() - 1) / 2])
}

/// Median of the recent local durations. `None` until at least one scan has
/// completed locally.
pub fn typical_scan_duration_secs() -> Option<u64> {
    typical_secs_from(&recent_scan_durations())
}

/// Format a duration as a lay-friendly "about N minutes" label.
fn format_minutes_label(secs: u64) -> String {
    let minutes = (secs as f64 / 60.0).round().max(1.0) as u64;
    if minutes == 1 {
        "about a minute".to_string()
    } else {
        format!("about {minutes} minutes")
    }
}

/// Human-readable estimate for a duration history: "about 3 minutes" from
/// observed history, or the deliberately vague "a few minutes" with no history
/// (calibrated so a typical 2-4 minute run never overshoots the stated
/// expectation).
fn typical_label_from(durations: &[u64]) -> String {
    // One observation is not a pattern: with fewer than two completed scans
    // the copy stays vague instead of turning a single sample into a precise
    // "about N minutes" (review nit on pick#610).
    match typical_secs_from(durations) {
        Some(secs) if durations.len() >= MIN_OBSERVATIONS => format_minutes_label(secs),
        _ => "a few minutes".to_string(),
    }
}

/// Bumped after every successful stats save. The label cache below keys on
/// it, so a fresh recording invalidates the memoized label without the
/// render path re-reading the file on every tick.
static STATS_GENERATION: AtomicU64 = AtomicU64::new(0);
struct LabelCache {
    generation: u64,
    label: String,
}
static LABEL_CACHE: OnceLock<Mutex<Option<LabelCache>>> = OnceLock::new();

/// Human-readable estimate for the user's own observed history.
///
/// Memoized: the call sites sit in per-second render paths (the progress
/// strip ticks once a second, and the Easy Mode hero re-renders with it),
/// so the stats file is read only when the history actually changed since
/// the last call (a successful [`record_scan_duration`]) — never per tick
/// (review nit on pick#610).
pub fn typical_scan_duration_label() -> String {
    let generation = STATS_GENERATION.load(Ordering::Relaxed);
    let cache = LABEL_CACHE.get_or_init(Default::default);
    let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(c) = guard.as_ref() {
        if c.generation == generation {
            return c.label.clone();
        }
    }
    let label = typical_label_from(&recent_scan_durations());
    *guard = Some(LabelCache {
        generation,
        label: label.clone(),
    });
    label
}

/// Whole seconds formatted as `m:ss` (e.g. "1:24"), for the live elapsed timer.
pub fn format_elapsed(secs: u64) -> String {
    let m = secs / 60;
    let s = secs % 60;
    format!("{m}:{s:02}")
}

/// True when the elapsed scan exceeds the hard cap that flags a stall
/// regardless of activity (a normal scan takes a few minutes, not 10+).
pub fn is_overall_stall(elapsed: Duration) -> bool {
    elapsed > Duration::from_secs(10 * 60)
}

/// True when the scan has been silent (no new messages or tool activity) long
/// enough that normal slowness stops being a reasonable explanation.
pub fn is_silence_stall(silence: Duration) -> bool {
    silence > Duration::from_secs(3 * 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Per-test temp file so the suite never touches the user's real
    /// `~/.config/pentest-connector/` state.
    fn temp_stats_file(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "pick-scan-stats-test-{}-{name}.json",
            std::process::id()
        ))
    }

    #[test]
    fn empty_history_yields_vague_label() {
        // No data, so the copy stays "a few minutes" rather than a fabricated
        // precise guess.
        assert_eq!(typical_secs_from(&[]), None);
        assert_eq!(typical_label_from(&[]), "a few minutes");
    }

    #[test]
    fn lower_median_of_durations() {
        // Lower median: with an even count the shorter value wins, so a
        // typical run does not overshoot the stated expectation.
        assert_eq!(typical_secs_from(&[120, 300, 180]), Some(180));
        assert_eq!(typical_secs_from(&[300, 120, 180, 240]), Some(180));
        assert_eq!(typical_secs_from(&[42]), Some(42));
    }

    #[test]
    fn format_minutes_labels() {
        assert_eq!(format_minutes_label(45), "about a minute");
        assert_eq!(format_minutes_label(75), "about a minute");
        assert_eq!(format_minutes_label(180), "about 3 minutes");
        assert_eq!(format_minutes_label(330), "about 6 minutes");
        assert_eq!(format_minutes_label(10), "about a minute");
    }

    #[test]
    fn typical_label_from_history() {
        assert_eq!(typical_label_from(&[180, 200]), "about 3 minutes");
        // n=1 stays vague: one completed scan is not a pattern yet.
        assert_eq!(typical_label_from(&[55]), "a few minutes");
        assert_eq!(typical_label_from(&[55, 65]), "about a minute");
    }

    #[test]
    fn format_elapsed_counts_up() {
        assert_eq!(format_elapsed(0), "0:00");
        assert_eq!(format_elapsed(84), "1:24");
        assert_eq!(format_elapsed(600), "10:00");
    }

    #[test]
    fn merge_entry_records_and_caps() {
        let mut d: Vec<u64> = Vec::new();
        for i in 1..=MAX_ENTRIES + 5 {
            merge_entry(&mut d, 60 + i as u64);
        }
        assert_eq!(d.len(), MAX_ENTRIES);
        // Oldest entries are the ones dropped.
        assert_eq!(*d.first().unwrap(), 60 + 6);
    }

    #[test]
    fn out_of_range_durations_are_dropped() {
        let mut d: Vec<u64> = Vec::new();
        merge_entry(&mut d, 5);
        merge_entry(&mut d, 999_999);
        merge_entry(&mut d, MIN_SECS - 1);
        assert!(d.is_empty());
    }

    #[test]
    fn record_and_read_back_roundtrip() {
        let path = temp_stats_file("roundtrip");
        let _ = fs::remove_file(&path);
        let mut stats = load_from(&path);
        merge_entry(&mut stats.durations_secs, 175);
        save_to(&path, &stats).unwrap();
        let read = load_from(&path).durations_secs;
        assert!(read.contains(&175), "recorded 175 not in {read:?}");
        let _ = fs::remove_file(&path);
    }

    /// Exercises the real `file_path()` wiring (the roundtrip test above
    /// bypasses it with temp paths) via the `PICK_SCAN_STATS_FILE` seam, and
    /// the memoized label end-to-end: record -> generation bump -> the label
    /// picks up the fresh history without an extra file read.
    #[test]
    fn record_scan_duration_file_path_wiring() {
        let path = temp_stats_file("file_path_wiring");
        let _ = fs::remove_file(&path);
        std::env::set_var("PICK_SCAN_STATS_FILE", &path);
        // n=1: recorded, but the label stays vague (single observation).
        record_scan_duration(175);
        assert_eq!(recent_scan_durations(), vec![175]);
        assert_eq!(typical_scan_duration_label(), "a few minutes");
        // n=2: the estimate turns specific (lower median of 175/205 is 175
        // -> "about 3 minutes"), and the memo reflects the new save.
        record_scan_duration(205);
        assert_eq!(recent_scan_durations(), vec![175, 205]);
        assert_eq!(typical_scan_duration_label(), "about 3 minutes");
        // A repeated read is served from the memo (no new save, same label).
        assert_eq!(typical_scan_duration_label(), "about 3 minutes");
        std::env::remove_var("PICK_SCAN_STATS_FILE");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn corrupt_file_falls_back_to_empty() {
        let path = temp_stats_file("corrupt");
        fs::write(&path, "{not json").unwrap();
        assert!(load_from(&path).durations_secs.is_empty());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn stall_thresholds() {
        assert!(!is_silence_stall(Duration::from_secs(179)));
        assert!(is_silence_stall(Duration::from_secs(181)));
        assert!(!is_overall_stall(Duration::from_secs(9 * 60)));
        assert!(is_overall_stall(Duration::from_secs(11 * 60)));
    }
}
