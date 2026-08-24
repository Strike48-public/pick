//! Custom [`metrics`] recorder that captures connector-defined metrics
//! for inclusion in `MetricsReport.custom_metrics`.
//!
//! The SDK installs this as the global recorder at startup. Connector
//! authors then use the standard `metrics` macros (`counter!`, `gauge!`,
//! `histogram!`) anywhere in their code and values are automatically
//! reported to the Matrix server.
//!
//! # Example
//!
//! ```rust,ignore
//! use metrics::{counter, gauge};
//!
//! // Inside your connector handler:
//! counter!("connector.requests_total").increment(1);
//! gauge!("connector.queue_depth").set(queue.len() as f64);
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use metrics::{
    Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
    SharedString, Unit,
};

// ---------------------------------------------------------------------------
// Atomic metric handles
// ---------------------------------------------------------------------------

struct SdkCounter(AtomicU64);

impl CounterFn for SdkCounter {
    fn increment(&self, value: u64) {
        self.0.fetch_add(value, Ordering::Relaxed);
    }
    fn absolute(&self, value: u64) {
        self.0.fetch_max(value, Ordering::Relaxed);
    }
}

struct SdkGauge(AtomicU64);

impl GaugeFn for SdkGauge {
    fn increment(&self, value: f64) {
        loop {
            let current = self.0.load(Ordering::Relaxed);
            let new_val = f64::from_bits(current) + value;
            if self
                .0
                .compare_exchange_weak(
                    current,
                    new_val.to_bits(),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                break;
            }
        }
    }
    fn decrement(&self, value: f64) {
        self.increment(-value);
    }
    fn set(&self, value: f64) {
        self.0.store(value.to_bits(), Ordering::Relaxed);
    }
}

struct SdkHistogram {
    count: AtomicU64,
    sum: AtomicU64, // f64 bits, updated via CAS
}

impl HistogramFn for SdkHistogram {
    fn record(&self, value: f64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        loop {
            let current = self.sum.load(Ordering::Relaxed);
            let new_val = f64::from_bits(current) + value;
            if self
                .sum
                .compare_exchange_weak(
                    current,
                    new_val.to_bits(),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                break;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shared storage (cloneable, passed to the metrics reporter task)
// ---------------------------------------------------------------------------

/// Thread-safe storage backing the SDK's global [`metrics`] recorder.
///
/// Clone this to share between the recorder (installed globally) and
/// the metrics reporter task that periodically snapshots values.
#[derive(Clone)]
pub(crate) struct MetricsStorage {
    counters: Arc<RwLock<HashMap<String, Arc<SdkCounter>>>>,
    gauges: Arc<RwLock<HashMap<String, Arc<SdkGauge>>>>,
    histograms: Arc<RwLock<HashMap<String, Arc<SdkHistogram>>>>,
}

impl MetricsStorage {
    pub fn new() -> Self {
        Self {
            counters: Arc::new(RwLock::new(HashMap::new())),
            gauges: Arc::new(RwLock::new(HashMap::new())),
            histograms: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Snapshot all recorded metrics as a flat `HashMap<String, f64>`.
    ///
    /// - **Counters** → current cumulative value
    /// - **Gauges** → current point-in-time value
    /// - **Histograms** → expanded to `{name}.count` and `{name}.avg`
    pub fn snapshot(&self) -> HashMap<String, f64> {
        let mut result = HashMap::new();

        if let Ok(counters) = self.counters.read() {
            for (name, c) in counters.iter() {
                result.insert(name.clone(), c.0.load(Ordering::Relaxed) as f64);
            }
        }

        if let Ok(gauges) = self.gauges.read() {
            for (name, g) in gauges.iter() {
                result.insert(name.clone(), f64::from_bits(g.0.load(Ordering::Relaxed)));
            }
        }

        if let Ok(histograms) = self.histograms.read() {
            for (name, h) in histograms.iter() {
                let count = h.count.load(Ordering::Relaxed);
                let sum = f64::from_bits(h.sum.load(Ordering::Relaxed));
                result.insert(format!("{name}.count"), count as f64);
                if count > 0 {
                    result.insert(format!("{name}.avg"), sum / count as f64);
                }
            }
        }

        result
    }
}

// ---------------------------------------------------------------------------
// Key serialisation (includes labels if present)
// ---------------------------------------------------------------------------

fn key_to_string(key: &Key) -> String {
    let name = key.name();
    let labels: Vec<String> = key
        .labels()
        .map(|l| format!("{}={}", l.key(), l.value()))
        .collect();
    if labels.is_empty() {
        name.to_string()
    } else {
        format!("{}{{{}}}", name, labels.join(","))
    }
}

// ---------------------------------------------------------------------------
// Recorder implementation
// ---------------------------------------------------------------------------

/// SDK recorder installed as the global [`metrics`] recorder.
///
/// Created via [`install`]. Not intended for direct use.
pub(crate) struct SdkRecorder {
    storage: MetricsStorage,
}

impl Recorder for SdkRecorder {
    fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _desc: SharedString) {}
    fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _desc: SharedString) {}
    fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _desc: SharedString) {}

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        let name = key_to_string(key);
        let mut map = self.storage.counters.write().unwrap();
        let arc = map
            .entry(name)
            .or_insert_with(|| Arc::new(SdkCounter(AtomicU64::new(0))));
        Counter::from_arc(arc.clone())
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        let name = key_to_string(key);
        let mut map = self.storage.gauges.write().unwrap();
        let arc = map
            .entry(name)
            .or_insert_with(|| Arc::new(SdkGauge(AtomicU64::new(0))));
        Gauge::from_arc(arc.clone())
    }

    fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        let name = key_to_string(key);
        let mut map = self.storage.histograms.write().unwrap();
        let arc = map.entry(name).or_insert_with(|| {
            Arc::new(SdkHistogram {
                count: AtomicU64::new(0),
                sum: AtomicU64::new(0),
            })
        });
        Histogram::from_arc(arc.clone())
    }
}

/// Process-wide handle to the SDK's `MetricsStorage`. Set on the first
/// successful [`install`] call; subsequent calls return clones of this so
/// every [`crate::ConnectorRunner`] in the same process shares one logical
/// storage. The underlying `Arc<RwLock<...>>` maps make these clones cheap
/// and safe to share.
static SDK_STORAGE: std::sync::OnceLock<MetricsStorage> = std::sync::OnceLock::new();

/// Install the SDK recorder as the global [`metrics`] recorder and return
/// the shared [`MetricsStorage`] for snapshot reads.
///
/// Idempotent across the process:
///
/// - First call (the SDK has not registered a global recorder yet):
///   creates a new `MetricsStorage`, registers the SDK recorder backed by
///   it, caches the storage in [`SDK_STORAGE`], returns a clone.
/// - Subsequent calls from the same process (e.g. a second
///   [`crate::ConnectorRunner`] in the same binary, or a
///   [`crate::MultiConnectorRunner`] running over WebSocket where each
///   registration spins up its own runner): return a clone of the cached
///   shared storage so the second runner's snapshot reads see the same
///   `metrics::counter!/gauge!/histogram!` values as the first.
/// - If a different recorder (not ours) is already installed (e.g. the
///   embedding application installed `metrics-exporter-prometheus`), we
///   leave it untouched and return a private empty storage. Connector
///   metrics emitted via the `metrics` crate flow to the application's
///   recorder; only `MetricsReport` snapshots from this runner will appear
///   empty. Logged at `debug!` (not `warn!`) since this is a supported
///   integration mode and the warning was a false positive in long-running
///   processes.
pub(crate) fn install() -> MetricsStorage {
    if let Some(existing) = SDK_STORAGE.get() {
        // SDK has already installed its recorder in this process; share the
        // single global storage so both runners' snapshots stay in sync.
        return existing.clone();
    }

    let storage = MetricsStorage::new();
    let recorder = SdkRecorder {
        storage: storage.clone(),
    };

    match metrics::set_global_recorder(recorder) {
        Ok(()) => {
            let _ = SDK_STORAGE.set(storage.clone());
            storage
        }
        Err(_) => recorder_unavailable_fallback(storage, &SDK_STORAGE),
    }
}

/// Resolution path for the `set_global_recorder` Err arm.
///
/// Two cases:
///
/// 1. We raced another concurrent SDK `install()` and lost. The SDK *is* the
///    global recorder, but the storage living behind it is the OTHER caller's
///    clone. We must hand back THAT storage so all callers in this process
///    share one logical snapshot. Without this fallback, the loser of the
///    race got an orphan `MetricsStorage` with no recorder writing to it and
///    every snapshot read returned zeros — exactly the bug the `install` doc
///    comment promised would not happen.
///
/// 2. The application installed a non-SDK recorder (e.g.
///    `metrics-exporter-prometheus`). `SDK_STORAGE` is empty in that process,
///    so the cached lookup misses and we fall through to returning the local
///    (orphan) storage. Metrics emitted via the `metrics` crate flow to the
///    application's recorder; `MetricsReport` snapshots from this runner will
///    appear empty, which is the documented integration mode.
fn recorder_unavailable_fallback(
    local: MetricsStorage,
    cache: &std::sync::OnceLock<MetricsStorage>,
) -> MetricsStorage {
    if let Some(shared) = cache.get() {
        return shared.clone();
    }
    tracing::debug!(
        "Strike48 SDK metrics recorder not installed: another \
         recorder is already global. Connector metrics via \
         metrics::counter!/gauge!/histogram! will flow to the \
         application's recorder, not to ConnectorRunner::report()."
    );
    local
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_storage() -> MetricsStorage {
        MetricsStorage::new()
    }

    fn make_recorder(storage: MetricsStorage) -> SdkRecorder {
        SdkRecorder { storage }
    }

    fn test_key(name: &str) -> Key {
        Key::from_name(name.to_string())
    }

    fn test_key_with_labels(name: &str, labels: &[(&str, &str)]) -> Key {
        let kvs: Vec<metrics::Label> = labels
            .iter()
            .map(|(k, v)| metrics::Label::new(k.to_string(), v.to_string()))
            .collect();
        Key::from_parts(name.to_string(), kvs)
    }

    #[test]
    fn test_counter_increment() {
        let storage = make_storage();
        let recorder = make_recorder(storage.clone());
        let key = test_key("my.counter");
        let meta = Metadata::new(module_path!(), metrics::Level::INFO, None);

        let counter = recorder.register_counter(&key, &meta);
        counter.increment(5);
        counter.increment(3);

        let snap = storage.snapshot();
        assert_eq!(snap["my.counter"], 8.0);
    }

    #[test]
    fn test_counter_absolute() {
        let storage = make_storage();
        let recorder = make_recorder(storage.clone());
        let key = test_key("abs.counter");
        let meta = Metadata::new(module_path!(), metrics::Level::INFO, None);

        let counter = recorder.register_counter(&key, &meta);
        counter.absolute(100);

        let snap = storage.snapshot();
        assert_eq!(snap["abs.counter"], 100.0);
    }

    #[test]
    fn test_gauge_set() {
        let storage = make_storage();
        let recorder = make_recorder(storage.clone());
        let key = test_key("my.gauge");
        let meta = Metadata::new(module_path!(), metrics::Level::INFO, None);

        let gauge = recorder.register_gauge(&key, &meta);
        gauge.set(42.5);

        let snap = storage.snapshot();
        assert_eq!(snap["my.gauge"], 42.5);
    }

    #[test]
    fn test_gauge_increment_decrement() {
        let storage = make_storage();
        let recorder = make_recorder(storage.clone());
        let key = test_key("inc.gauge");
        let meta = Metadata::new(module_path!(), metrics::Level::INFO, None);

        let gauge = recorder.register_gauge(&key, &meta);
        gauge.set(10.0);
        gauge.increment(5.0);
        gauge.decrement(3.0);

        let snap = storage.snapshot();
        assert_eq!(snap["inc.gauge"], 12.0);
    }

    #[test]
    fn test_histogram_records() {
        let storage = make_storage();
        let recorder = make_recorder(storage.clone());
        let key = test_key("my.hist");
        let meta = Metadata::new(module_path!(), metrics::Level::INFO, None);

        let hist = recorder.register_histogram(&key, &meta);
        hist.record(10.0);
        hist.record(20.0);
        hist.record(30.0);

        let snap = storage.snapshot();
        assert_eq!(snap["my.hist.count"], 3.0);
        assert_eq!(snap["my.hist.avg"], 20.0);
    }

    #[test]
    fn test_labeled_metrics() {
        let storage = make_storage();
        let recorder = make_recorder(storage.clone());
        let key_get = test_key_with_labels("http.requests", &[("method", "GET")]);
        let key_post = test_key_with_labels("http.requests", &[("method", "POST")]);
        let meta = Metadata::new(module_path!(), metrics::Level::INFO, None);

        let c_get = recorder.register_counter(&key_get, &meta);
        let c_post = recorder.register_counter(&key_post, &meta);
        c_get.increment(10);
        c_post.increment(3);

        let snap = storage.snapshot();
        assert_eq!(snap["http.requests{method=GET}"], 10.0);
        assert_eq!(snap["http.requests{method=POST}"], 3.0);
    }

    #[test]
    fn test_same_key_returns_same_handle() {
        let storage = make_storage();
        let recorder = make_recorder(storage.clone());
        let key = test_key("shared.counter");
        let meta = Metadata::new(module_path!(), metrics::Level::INFO, None);

        let c1 = recorder.register_counter(&key, &meta);
        let c2 = recorder.register_counter(&key, &meta);
        c1.increment(5);
        c2.increment(3);

        let snap = storage.snapshot();
        assert_eq!(snap["shared.counter"], 8.0);
    }

    #[test]
    fn test_empty_snapshot() {
        let storage = make_storage();
        let snap = storage.snapshot();
        assert!(snap.is_empty());
    }

    #[test]
    fn test_key_to_string_no_labels() {
        let key = test_key("simple.metric");
        assert_eq!(key_to_string(&key), "simple.metric");
    }

    #[test]
    fn test_key_to_string_with_labels() {
        let key = test_key_with_labels("req", &[("method", "GET"), ("status", "200")]);
        let s = key_to_string(&key);
        assert!(s.starts_with("req{"));
        assert!(s.contains("method=GET"));
        assert!(s.contains("status=200"));
    }

    #[test]
    fn recorder_unavailable_fallback_returns_winner_storage_on_lost_race() {
        // Simulates the case where a concurrent install() won
        // set_global_recorder and stored its storage in the cache. The
        // loser's Err arm must hand back the cached (winner) storage, not
        // its own orphan clone.
        let cache: std::sync::OnceLock<MetricsStorage> = std::sync::OnceLock::new();
        let winner = MetricsStorage::new();
        if cache.set(winner.clone()).is_err() {
            unreachable!("OnceLock was just constructed");
        }

        let loser_local = MetricsStorage::new();
        let resolved = recorder_unavailable_fallback(loser_local, &cache);

        // Drive a counter through a recorder backed by `winner` and observe
        // it via the `resolved` snapshot. They must share the same Arcs.
        let recorder = SdkRecorder {
            storage: winner.clone(),
        };
        let key = test_key("strike48.test.lost_race");
        let meta = Metadata::new(module_path!(), metrics::Level::INFO, None);
        let counter = recorder.register_counter(&key, &meta);
        counter.increment(7);

        let snap = resolved.snapshot();
        assert_eq!(
            snap.get("strike48.test.lost_race").copied(),
            Some(7.0),
            "fallback storage must alias the cached winner storage"
        );
    }

    #[test]
    fn recorder_unavailable_fallback_returns_local_when_cache_empty() {
        // Application owns the global recorder and the SDK never raced —
        // the cache is empty. We must hand back the local storage so the
        // caller still has a valid (if orphan) `MetricsStorage` to read.
        let cache: std::sync::OnceLock<MetricsStorage> = std::sync::OnceLock::new();
        let local = MetricsStorage::new();
        let resolved = recorder_unavailable_fallback(local.clone(), &cache);

        // Write through `local` and confirm `resolved` sees it (proves they
        // are the same logical storage).
        let recorder = SdkRecorder {
            storage: local.clone(),
        };
        let key = test_key("strike48.test.local_fallback");
        let meta = Metadata::new(module_path!(), metrics::Level::INFO, None);
        recorder.register_counter(&key, &meta).increment(3);

        let snap = resolved.snapshot();
        assert_eq!(snap["strike48.test.local_fallback"], 3.0);
    }

    #[test]
    fn install_is_idempotent_within_a_process() {
        // Two consecutive install() calls in the same process must succeed
        // and yield handles to the SAME underlying storage. This is the
        // shape of the bug we fixed: previously the second runner got an
        // orphan storage and lost all metrics.
        //
        // Note: install() registers a global recorder. Other tests in this
        // module exercise SdkRecorder directly without touching the global,
        // so this test (and only this test) interacts with the singleton.
        let first = install();
        let second = install();

        // Manually exercise the global recorder by emitting a counter
        // through the `metrics` facade. Both handles must observe the
        // same value in their snapshot.
        metrics::counter!("strike48.test.idempotent_install").increment(7);

        let s1 = first.snapshot();
        let s2 = second.snapshot();

        // Either the SDK recorder is the global one (cooperating test
        // environment) and both snapshots see the counter, or some other
        // recorder is global (rare in unit tests but possible in
        // integration scenarios) and both snapshots are empty. Either way
        // the two storages must agree.
        assert_eq!(s1, s2, "second install must share storage with first");
    }
}
