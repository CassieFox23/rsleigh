//! Cards keep code reached through jumps that leave the linear window and
//! report control flow they could not follow (morluto/rea#1389).
//! Fixture: test-harness/fixtures/elf/cold_split (stripped x86-64 ELF).

use serde_json::Value;
use std::process::Command;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../test-harness/fixtures/elf/cold_split/cold_split.elf"
);
const CHECK: &str = "0x401262";
const DISPATCH: &str = "0x40126e";

fn card(function: &str, extra: &[&str]) -> (i32, Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_rsleigh"))
        .args([FIXTURE, function, "--card", "--json", "--decompile"])
        .args(extra)
        .output()
        .unwrap();
    let value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code().unwrap(), value)
}

#[test]
fn cold_part_below_the_function_is_part_of_its_body() {
    let (code, card) = card(CHECK, &[]);
    assert_eq!(code, 0, "{card}");
    assert_eq!(card["status"], "ok", "{card}");
    let text = card["pseudocode"]["text"].as_str().unwrap();
    // The unlikely path lives in check.cold, which discovery also lists as
    // a function; it must be inlined, not shown as a tail call or dropped.
    assert!(text.contains("\"negative input\""), "{text}");
    assert!(!text.contains("return func_40123c"), "{text}");
    let listed: Vec<&str> = card["instructions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["address"].as_str().unwrap())
        .collect();
    assert_eq!(
        listed.first(),
        Some(&"0x40123c"),
        "address order: {listed:?}"
    );
}

#[test]
fn unrecovered_jump_table_makes_the_card_partial() {
    let (code, card) = card(DISPATCH, &[]);
    assert_eq!(code, 2, "{card}");
    assert_eq!(card["status"], "partial", "{card}");
    let diagnostic = card["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["code"] == "unresolved_control_flow")
        .unwrap_or_else(|| panic!("{card}"));
    assert_eq!(diagnostic["address"], "0x401283");
    // Case bodies are only reachable through the table; none may be
    // presented as the function's fallthrough result.
    let text = card["pseudocode"]["text"].as_str().unwrap();
    assert!(!text.contains("return 10"), "{text}");
    assert!(!text.contains("return 20"), "{text}");
}

#[test]
fn partial_cards_with_function_diagnostics_are_cached() {
    let cache = std::env::temp_dir().join(format!(
        "rsleigh-control-flow-cache-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let flags = ["--analysis-cache", cache.to_str().unwrap()];
    let (_, first) = card(DISPATCH, &flags);
    let (code, second) = card(DISPATCH, &flags);
    assert_eq!(code, 2, "{second}");
    assert_eq!(first["metrics"]["cache"], "miss", "{first}");
    assert_eq!(second["metrics"]["cache"], "hit", "{second}");
    assert_eq!(second["diagnostics"], first["diagnostics"]);
    assert_eq!(second["pseudocode"], first["pseudocode"]);
    std::fs::remove_dir_all(cache).unwrap();
}
