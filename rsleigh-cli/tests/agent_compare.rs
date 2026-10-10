//! Structured function comparison: relocation, deliberate changes, duplicate
//! and renamed functions, failed or truncated input, and incompatible
//! profiles. No failed or incomplete case may become an unexplained
//! "unchanged" result.
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

#[path = "../../test-harness/fixtures/agent-re/seed.rs"]
mod seed;
use seed as re_seed;
#[path = "../../test-harness/fixtures/agent-re/corpus.rs"]
mod corpus;
#[path = "../../test-harness/fixtures/agent-re/traversal.rs"]
mod traversal;
#[path = "../../test-harness/fixtures/agent-re/variants.rs"]
mod variants;

fn scratch() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "rsleigh-agent-compare-{}-{nonce}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn write(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = root.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn compare(old: &Path, new: &Path, extra: &[&str]) -> (i32, Value) {
    let output = Command::new(RSLEIGH_BIN)
        .arg(old)
        .arg("--compare")
        .arg(new)
        .arg("--json")
        .args(extra)
        .output()
        .unwrap();
    let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code().unwrap(), value)
}

fn pair<'a>(model: &'a Value, name: &str) -> &'a Value {
    model["pairs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["old"]["name"] == name)
        .unwrap_or_else(|| panic!("no pair {name}: {model}"))
}

fn result<'a>(pair: &'a Value, dimension: &str) -> &'a str {
    pair["dimensions"][dimension]["result"].as_str().unwrap()
}

/// Every unchanged verdict must be complete evidence on both sides.
fn assert_no_unexplained_unchanged(model: &Value) {
    for pair in model["pairs"].as_array().unwrap() {
        if pair["verdict"] == "unchanged" {
            assert_eq!(pair["old"]["complete"], true, "{pair}");
            assert_eq!(pair["new"]["complete"], true, "{pair}");
            for (name, dimension) in pair["dimensions"].as_object().unwrap() {
                assert_ne!(dimension["result"], "unknown", "{name}: {pair}");
            }
            assert!(pair["explanation"].is_string());
        }
    }
}

#[test]
fn relocation_and_deliberate_changes_are_classified_by_dimension() {
    let root = scratch();
    let old = write(&root, "old.exe", &seed::binary());
    let (code, same) = compare(&old, &old, &[]);
    assert_eq!(code, 0, "{same}");
    assert_eq!(same["schema"], "rsleigh.function-comparison/v1");
    assert_eq!(same["summary"]["unchanged"], 5);

    let moved = write(&root, "moved.exe", &variants::relocated());
    let (code, model) = compare(&old, &moved, &[]);
    assert_eq!(code, 0, "{model}");
    let calls = pair(&model, "calls");
    assert_eq!(calls["new"]["address"], "0x4010a0");
    assert_eq!(
        result(calls, "bytes"),
        "changed",
        "rel32 displacements moved"
    );
    assert_eq!(result(calls, "instructions"), "unchanged");
    assert_eq!(calls["verdict"], "unchanged");
    assert!(calls["explanation"]
        .as_str()
        .unwrap()
        .contains("relocation"));
    assert_no_unexplained_unchanged(&model);

    let constant = write(&root, "constant.exe", &variants::changed_constant());
    let (code, model) = compare(&old, &constant, &[]);
    assert_eq!(code, 0);
    let changed = pair(&model, "constant");
    assert_eq!(changed["verdict"], "changed");
    assert_eq!(result(changed, "instructions"), "changed");
    assert_eq!(result(changed, "calls"), "unchanged");
    let diff = changed["dimensions"]["pseudocode"]["detail"]["diff"]
        .as_array()
        .unwrap();
    assert!(
        diff.iter().any(|l| l == "- return 7;") && diff.iter().any(|l| l == "+ return 8;"),
        "{diff:?}"
    );
    assert_eq!(model["summary"]["changed"], 1);

    let callee = write(&root, "callee.exe", &variants::changed_callee());
    let (_, model) = compare(&old, &callee, &["--pair", "calls"]);
    let calls = pair(&model, "calls");
    assert_eq!(calls["verdict"], "changed");
    assert_eq!(result(calls, "calls"), "changed");
    assert_eq!(
        calls["dimensions"]["calls"]["detail"]["new"],
        serde_json::json!(["sym:constant", "sym:helper"])
    );
    assert_eq!(calls["match"], "explicit");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn duplicate_and_renamed_functions_stay_unmatched_or_ambiguous() {
    let root = scratch();
    let old = write(&root, "old.exe", &seed::binary());
    let duplicate = write(&root, "duplicate.exe", &variants::duplicate_name());
    let (code, model) = compare(&old, &duplicate, &[]);
    assert_eq!(code, 2, "{model}");
    assert_eq!(model["ambiguous"][0]["name"], "helper");
    assert_eq!(
        model["ambiguous"][0]["new"],
        serde_json::json!(["0x401060", "0x401080"])
    );
    assert!(model["pairs"]
        .as_array()
        .unwrap()
        .iter()
        .all(|p| p["old"]["name"] != "helper"));
    let (_, explicit) = compare(
        &old,
        &duplicate,
        &["--pair", "helper", "--pair", "helper:0x401080"],
    );
    assert_eq!(
        explicit["unresolved_requests"][0]["new"]["reason"],
        "ambiguous_name"
    );
    assert_eq!(explicit["pairs"].as_array().unwrap().len(), 1);
    assert_eq!(explicit["pairs"][0]["new"]["address"], "0x401080");

    // PE inventories are partial: an unmatched name is unknown, not removed.
    let renamed = write(&root, "renamed.exe", &variants::renamed());
    let (code, model) = compare(&old, &renamed, &[]);
    assert_eq!(code, 2);
    let statuses: Vec<(&str, &str)> = model["unmatched"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| (u["name"].as_str().unwrap(), u["status"].as_str().unwrap()))
        .collect();
    assert_eq!(statuses, [("load", "unknown"), ("lode", "unknown")]);
    assert_eq!(model["suggestions"][0]["established"], false);
    assert_eq!(model["suggestions"][0]["new"]["name"], "lode");

    // An unstripped ELF symbol table is a complete inventory: names missing
    // from it are absent. References to the renamed helper stay unmapped.
    let dispatch = corpus::tasks()
        .into_iter()
        .find(|t| t.id == "x64-dispatch")
        .unwrap()
        .data;
    let elf_old = write(&root, "dispatch.elf", &dispatch);
    let mut elf_new = dispatch.clone();
    let at = elf_new.windows(7).position(|w| w == b"helper\0").unwrap();
    elf_new[at..at + 6].copy_from_slice(b"helpex");
    let elf_new = write(&root, "renamed.elf", &elf_new);
    let (_, model) = compare(&elf_old, &elf_new, &[]);
    assert_eq!(model["old"]["inventory"]["complete"], true);
    let statuses: Vec<&str> = model["unmatched"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["status"].as_str().unwrap())
        .collect();
    assert_eq!(statuses, ["absent", "absent"]);
    let entry = pair(&model, "entry");
    assert_eq!(result(entry, "instructions"), "unknown");
    assert_eq!(
        entry["dimensions"]["instructions"]["reason"],
        "unmapped_reference"
    );
    assert_eq!(
        entry["dimensions"]["calls"]["reason"],
        "unresolved_indirect_call"
    );
    assert_eq!(entry["verdict"], "unknown");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_truncated_and_incompatible_inputs_never_look_unchanged() {
    let root = scratch();
    let old = write(&root, "old.exe", &seed::binary());
    let garbage = write(&root, "garbage.bin", b"not a binary");
    let (code, failed) = compare(&old, &garbage, &[]);
    assert_eq!(code, 1);
    assert_eq!(failed["error_code"], "unsupported_format");
    let (code, missing) = compare(&old, &root.join("absent.exe"), &[]);
    assert_eq!(code, 1);
    assert_eq!(missing["error_code"], "input_unreadable");

    let (code, model) = compare(&old, &old, &["--pair", "0x401000:0x40fff00"]);
    assert_eq!(code, 2);
    assert_eq!(model["pairs"][0]["verdict"], "unknown");
    assert_eq!(
        model["pairs"][0]["dimensions"]["bytes"]["reason"],
        "decode_failed"
    );

    // `load` falls through into an undecodable byte: identical but truncated.
    let truncated = write(&root, "truncated.exe", &variants::truncated());
    let (code, model) = compare(&truncated, &truncated, &["--pair", "load"]);
    assert_eq!(code, 2, "{model}");
    let load = &model["pairs"][0];
    assert_eq!(load["verdict"], "unknown");
    assert_eq!(load["new"]["complete"], false);
    assert!(load["new"]["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["code"] == "body_truncated"));
    assert_eq!(model["status"], "partial");

    let elf = corpus::tasks()
        .into_iter()
        .find(|t| t.id == "x64-dispatch")
        .unwrap()
        .data;
    let elf = write(&root, "dispatch.elf", &elf);
    let (code, model) = compare(&old, &elf, &["--pair", "constant:entry"]);
    assert_eq!(code, 2);
    assert_eq!(model["profile"]["compatible"], false);
    let crossed = &model["pairs"][0];
    assert_eq!(crossed["verdict"], "unknown");
    for dimension in ["instructions", "calls", "strings", "cfg", "pseudocode"] {
        assert_eq!(
            crossed["dimensions"][dimension]["reason"], "incompatible_profile",
            "{dimension}"
        );
    }
    assert_no_unexplained_unchanged(&model);

    let (code, limited) = compare(&old, &old, &["--limit", "2"]);
    assert_eq!(code, 2);
    assert_eq!(limited["limits"]["pairs_truncated"], true);
    assert_eq!(limited["limits"]["pairs_total"], 5);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn text_legacy_diff_and_evidence_share_the_model() {
    let root = scratch();
    let old = write(&root, "old.exe", &seed::binary());
    let new = write(&root, "new.exe", &variants::changed_constant());
    let text = Command::new(RSLEIGH_BIN)
        .arg(&old)
        .arg("--compare")
        .arg(&new)
        .output()
        .unwrap();
    assert_eq!(text.status.code(), Some(0));
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(
        text.contains("=== CHANGED: constant (0x401000 -> 0x401000) ==="),
        "{text}"
    );
    assert!(
        text.contains("Changed:   1") && text.contains("Unchanged: 4"),
        "{text}"
    );
    let legacy = Command::new(RSLEIGH_BIN)
        .arg(&old)
        .arg("--diff")
        .arg(&new)
        .output()
        .unwrap();
    let legacy = String::from_utf8(legacy.stdout).unwrap();
    assert!(legacy.contains("=== CHANGED: constant"), "{legacy}");
    assert!(legacy.contains("\x1b[31m- return 7;\x1b[0m"), "{legacy}");
    assert!(
        !legacy.contains("=== UNCHANGED"),
        "legacy diff hides unchanged pairs"
    );

    // Evidence identifies the comparison binary by content, not path.
    let record = |new: &Path| {
        let out = Command::new(RSLEIGH_BIN)
            .arg(&old)
            .arg("--compare")
            .arg(new)
            .arg("--evidence")
            .output()
            .unwrap();
        serde_json::from_slice::<Value>(&out.stdout).unwrap()
    };
    let first = record(&new);
    assert_eq!(first["kind"], "compare");
    assert_eq!(first["payload"]["schema"], "rsleigh.function-comparison/v1");
    assert!(first["operation"]["parameters"]["compare"]["sha256"].is_string());
    let copy = root.join("elsewhere.exe");
    std::fs::copy(&new, &copy).unwrap();
    assert_eq!(record(&copy)["id"], first["id"]);
    std::fs::remove_dir_all(root).unwrap();
}
