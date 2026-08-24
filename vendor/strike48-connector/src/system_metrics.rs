//! System and process resource metrics.
//!
//! Collects host-level and process-level metrics via `sysinfo` for
//! inclusion in `MetricsReport.custom_metrics` under the `sdk.` prefix.
//!
//! Designed to be called periodically (every metrics interval) — the
//! `System` instance is kept alive across calls so CPU usage deltas
//! are meaningful.

use std::collections::HashMap;
use std::sync::Mutex;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

/// Lazily-initialized, reusable `System` instance.
///
/// `sysinfo` requires diffing between consecutive refreshes for CPU
/// usage to produce meaningful values. A global instance ensures the
/// second and subsequent calls return real deltas rather than zero.
static SYSTEM: Mutex<Option<System>> = Mutex::new(None);

fn with_system<F, R>(f: F) -> R
where
    F: FnOnce(&mut System) -> R,
{
    let mut guard = SYSTEM.lock().unwrap_or_else(|e| e.into_inner());
    let sys = guard.get_or_insert_with(|| {
        System::new_with_specifics(
            RefreshKind::nothing()
                .with_memory(sysinfo::MemoryRefreshKind::everything())
                .with_cpu(sysinfo::CpuRefreshKind::nothing().with_cpu_usage()),
        )
    });
    f(sys)
}

/// Collect system and process resource metrics.
///
/// Returns a map with `sdk.*` prefixed keys suitable for merging into
/// `MetricsReport.custom_metrics`.
pub(crate) fn collect() -> HashMap<String, f64> {
    let mut m = HashMap::new();

    with_system(|sys| {
        sys.refresh_memory();
        sys.refresh_cpu_usage();

        // System memory
        m.insert(
            "sdk.system_total_memory_bytes".into(),
            sys.total_memory() as f64,
        );
        m.insert(
            "sdk.system_used_memory_bytes".into(),
            sys.used_memory() as f64,
        );
        m.insert(
            "sdk.system_available_memory_bytes".into(),
            sys.available_memory() as f64,
        );
        m.insert(
            "sdk.system_total_swap_bytes".into(),
            sys.total_swap() as f64,
        );
        m.insert("sdk.system_used_swap_bytes".into(), sys.used_swap() as f64);

        // CPU
        m.insert("sdk.system_cpu_count".into(), sys.cpus().len() as f64);
        m.insert(
            "sdk.system_cpu_usage_percent".into(),
            sys.global_cpu_usage() as f64,
        );

        // Load average
        let load = System::load_average();
        m.insert("sdk.system_load_avg_1m".into(), load.one);
        m.insert("sdk.system_load_avg_5m".into(), load.five);
        m.insert("sdk.system_load_avg_15m".into(), load.fifteen);

        // Process metrics (our own process)
        let pid = sysinfo::get_current_pid().ok();
        if let Some(pid) = pid {
            sys.refresh_processes_specifics(
                ProcessesToUpdate::Some(&[pid]),
                false,
                ProcessRefreshKind::nothing()
                    .with_memory()
                    .with_cpu()
                    .with_disk_usage(),
            );

            if let Some(proc) = sys.process(pid) {
                m.insert("sdk.process_memory_bytes".into(), proc.memory() as f64);
                m.insert(
                    "sdk.process_virtual_memory_bytes".into(),
                    proc.virtual_memory() as f64,
                );
                m.insert(
                    "sdk.process_cpu_usage_percent".into(),
                    proc.cpu_usage() as f64,
                );

                let disk = proc.disk_usage();
                m.insert("sdk.process_disk_read_bytes".into(), disk.read_bytes as f64);
                m.insert(
                    "sdk.process_disk_written_bytes".into(),
                    disk.written_bytes as f64,
                );
            }
        }
    });

    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_returns_system_keys() {
        let m = collect();

        let required = [
            "sdk.system_total_memory_bytes",
            "sdk.system_used_memory_bytes",
            "sdk.system_available_memory_bytes",
            "sdk.system_cpu_count",
            "sdk.system_cpu_usage_percent",
            "sdk.system_load_avg_1m",
            "sdk.system_load_avg_5m",
            "sdk.system_load_avg_15m",
        ];

        for key in required {
            assert!(m.contains_key(key), "missing key: {key}");
        }
    }

    #[test]
    fn test_collect_returns_process_keys() {
        let m = collect();

        let required = [
            "sdk.process_memory_bytes",
            "sdk.process_virtual_memory_bytes",
            "sdk.process_cpu_usage_percent",
        ];

        for key in required {
            assert!(m.contains_key(key), "missing key: {key}");
        }
    }

    #[test]
    fn test_total_memory_is_positive() {
        let m = collect();
        let total = m["sdk.system_total_memory_bytes"];
        assert!(total > 0.0, "total memory must be positive, got {total}");
    }

    #[test]
    fn test_cpu_count_is_positive() {
        let m = collect();
        let count = m["sdk.system_cpu_count"];
        assert!(count >= 1.0, "cpu count must be >= 1, got {count}");
    }

    #[test]
    fn test_process_memory_is_positive() {
        let m = collect();
        let rss = m["sdk.process_memory_bytes"];
        assert!(rss > 0.0, "process RSS must be positive, got {rss}");
    }

    #[test]
    fn test_all_keys_have_sdk_prefix() {
        let m = collect();
        for key in m.keys() {
            assert!(key.starts_with("sdk."), "key {key} must have sdk. prefix");
        }
    }

    #[test]
    fn test_used_memory_less_than_total() {
        let m = collect();
        let total = m["sdk.system_total_memory_bytes"];
        let used = m["sdk.system_used_memory_bytes"];
        assert!(
            used <= total,
            "used memory ({used}) should not exceed total ({total})"
        );
    }

    #[test]
    fn test_collect_is_idempotent() {
        let m1 = collect();
        let m2 = collect();
        assert_eq!(
            m1.len(),
            m2.len(),
            "consecutive calls should return same number of keys"
        );
    }
}
