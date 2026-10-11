//! Cards keep code reached through jumps that leave the linear window and
//! report control flow they could not follow (morluto/rea#1389).
//! Fixture: test-harness/fixtures/elf/cold_split (stripped x86-64 ELF).

use serde_json::Value;
use std::process::Command;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../test-harness/fixtures/elf/cold_split/cold_split.elf"
);
const COLD: &str = "0x401254";
const CHECK: &str = "0x40127a";
const DISPATCH: &str = "0x401286";
const COMPUTED: &str = "0x4012ae";

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
    assert!(!text.contains("return func_401254"), "{text}");
    let listed: Vec<&str> = card["instructions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["address"].as_str().unwrap())
        .collect();
    assert_eq!(listed.first(), Some(&COLD), "address order: {listed:?}");
}

#[test]
fn cold_part_is_not_listed_as_a_function() {
    let out = Command::new(env!("CARGO_BIN_EXE_rsleigh"))
        .arg(FIXTURE)
        .output()
        .unwrap();
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(listing.contains("0x0040127a"), "{listing}");
    assert!(!listing.contains("0x00401254"), "{listing}");
}

#[test]
fn jump_table_cases_are_recovered() {
    let (code, card) = card(DISPATCH, &[]);
    assert_eq!(code, 0, "{card}");
    assert_eq!(card["status"], "ok", "{card}");
    let text = card["pseudocode"]["text"].as_str().unwrap();
    // Table entries: 0 -> 10, 1 -> 20, 2 -> the default 0.
    assert!(text.contains("== 1") || text.contains("case 1"), "{text}");
    assert!(text.contains("return 10;"), "{text}");
    assert!(text.contains("return 20;"), "{text}");
}

#[test]
fn computed_jump_without_a_table_makes_the_card_partial() {
    let (code, card) = card(COMPUTED, &[]);
    assert_eq!(code, 2, "{card}");
    assert_eq!(card["status"], "partial", "{card}");
    let diagnostic = card["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["code"] == "unresolved_control_flow")
        .unwrap_or_else(|| panic!("{card}"));
    assert_eq!(diagnostic["address"], "0x4012b8");
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
    let (_, first) = card(COMPUTED, &flags);
    let (code, second) = card(COMPUTED, &flags);
    assert_eq!(code, 2, "{second}");
    assert_eq!(first["metrics"]["cache"], "miss", "{first}");
    assert_eq!(second["metrics"]["cache"], "hit", "{second}");
    assert_eq!(second["diagnostics"], first["diagnostics"]);
    assert_eq!(second["pseudocode"], first["pseudocode"]);
    std::fs::remove_dir_all(cache).unwrap();
}
