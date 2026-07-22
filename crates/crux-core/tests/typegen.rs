// Gated: only runs with --features codegen (facet_typegen). Verifies Swift +
// Kotlin generation succeeds and emits our core types.
#![cfg(feature = "codegen")]

use std::process::Command;

#[test]
fn generates_swift_and_kotlin_types() {
    let tmp = std::env::temp_dir().join(format!("pick-crux-typegen-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    for lang in ["swift", "kotlin"] {
        let status = Command::new(env!("CARGO"))
            .args(["run", "--quiet", "--bin", "codegen", "--features", "codegen", "--",
                   lang, tmp.to_str().unwrap()])
            .status()
            .expect("run codegen");
        assert!(status.success(), "codegen failed for {lang}");
    }
    // Some output file mentions ViewModel and Event.
    let mut found_vm = false;
    let mut found_ev = false;
    for entry in walk(&tmp) {
        let s = std::fs::read_to_string(&entry).unwrap_or_default();
        if s.contains("ViewModel") { found_vm = true; }
        if s.contains("Event") { found_ev = true; }
    }
    assert!(found_vm, "generated types should contain ViewModel");
    assert!(found_ev, "generated types should contain Event");
    let _ = std::fs::remove_dir_all(&tmp);
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = vec![];
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() { out.extend(walk(&p)); } else { out.push(p); }
        }
    }
    out
}
