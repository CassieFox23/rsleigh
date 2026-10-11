//! A switch whose table base is set far from the jump no longer leaves the
//! card `partial` with `unresolved_control_flow`.
//! Fixture: test-harness/fixtures/elf/jump_tables (stripped x86-64 ELF).

use serde_json::Value;
use std::process::Command;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../test-harness/fixtures/elf/jump_tables/jump_tables.elf"
);
const FAR_BASE: &str = "0x4016e1";

fn card(function: &str) -> (i32, Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_rsleigh"))
        .args([FIXTURE, function, "--card", "--json", "--decompile"])
        .output()
        .unwrap();
    let value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stdout)));
    (out.status.code().unwrap(), value)
}

#[test]
fn distant_table_base_gives_an_ok_card_with_both_cases() {
    let (code, card) = card(FAR_BASE);
    assert_eq!(code, 0, "{card}");
    assert_eq!(card["status"], "ok", "{card}");
    let text = card["pseudocode"]["text"].as_str().unwrap();
    assert!(text.contains("return 30;"), "{text}");
    assert!(text.contains("return 31;"), "{text}");
}
