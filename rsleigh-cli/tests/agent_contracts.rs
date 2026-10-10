//! Capability catalog drift tests: every advertised example runs with its
//! documented schema and exit status, and invalid input has stable codes.
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

fn scratch() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "rsleigh-agent-contracts-{}-{nonce}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn run(args: &[&str], cwd: &Path) -> (i32, Vec<u8>, String) {
    let output = Command::new(RSLEIGH_BIN)
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap();
    (
        output.status.code().expect("CLI must exit normally"),
        output.stdout,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn run_json(args: &[&str], cwd: &Path) -> (i32, Value) {
    let (code, stdout, stderr) = run(args, cwd);
    let value = serde_json::from_slice(&stdout).unwrap_or_else(|_| {
        panic!(
            "{args:?}\nstdout: {}\nstderr: {stderr}",
            String::from_utf8_lossy(&stdout)
        )
    });
    (code, value)
}

fn catalog(cwd: &Path) -> Value {
    let (code, value) = run_json(&["--capabilities", "--json"], cwd);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["schema"], "rsleigh.capabilities/v1");
    value
}

#[test]
fn advertised_examples_execute_with_their_schema_and_exit_status() {
    let root = scratch();
    let binary = root.join("seed.exe");
    std::fs::write(&binary, seed::binary()).unwrap();
    let directory = root.join("out");
    let store = root.join("store");
    let bundle = root.join("bundle");
    let catalog = catalog(&root);
    let operations = catalog["operations"].as_array().unwrap();
    assert!(operations.len() >= 5);
    for op in operations {
        for example in op["examples"].as_array().unwrap() {
            let argv: Vec<String> = example["argv"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| match a.as_str().unwrap() {
                    "FILE" => binary.to_str().unwrap().to_string(),
                    "FUNCTION" => "0x401000".to_string(),
                    "DIR" => directory.to_str().unwrap().to_string(),
                    "STORE" => store.to_str().unwrap().to_string(),
                    "BUNDLE" => bundle.to_str().unwrap().to_string(),
                    other => other.to_string(),
                })
                .collect();
            let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
            let (code, value) = run_json(&argv, &root);
            let exits: Vec<i64> = example["exits"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e.as_i64().unwrap())
                .collect();
            assert!(
                exits.contains(&i64::from(code)),
                "{argv:?} exit {code}: {value}"
            );
            assert_ne!(value["status"], "failed", "{argv:?}: {value}");
            let captures = op["flags"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["name"] == "--evidence");
            if captures
                && argv
                    .iter()
                    .any(|a| *a == "--evidence" || *a == "--evidence-store")
            {
                // Evidence capture wraps the operation's unchanged payload.
                assert_eq!(value["schema"], "rsleigh.evidence/v1", "{argv:?}");
                assert_eq!(value["payload"]["schema"], op["schema"], "{argv:?}");
                assert_eq!(value["kind"], op["id"]);
            } else {
                assert_eq!(value["schema"], op["schema"], "{argv:?}");
            }
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn target_free_discovery_reads_no_target_and_matches_help_and_version() {
    // An empty working directory: discovery has no binary to read.
    let root = scratch();
    let catalog = catalog(&root);
    assert_eq!(catalog["tool"]["version"], env!("CARGO_PKG_VERSION"));
    assert!(catalog["tool"]["build"]["id"]
        .as_str()
        .is_some_and(|id| !id.is_empty()));
    let (code, stdout, _) = run(&["--help"], &root);
    assert_eq!(code, 0);
    let help = String::from_utf8(stdout).unwrap();
    for op in catalog["operations"].as_array().unwrap() {
        assert!(help.contains(op["usage"].as_str().unwrap()), "{op}");
    }
    let (code, stdout, _) = run(&["--version"], &root);
    assert_eq!(code, 0);
    assert_eq!(
        String::from_utf8(stdout).unwrap().trim(),
        format!("rsleigh {}", env!("CARGO_PKG_VERSION"))
    );
    let (code, version) = run_json(&["--version", "--json"], &root);
    assert_eq!(code, 0);
    assert_eq!(version["tool"], catalog["tool"]);
    // Bare invocation keeps its scripting contract: usage on stderr, exit 1.
    let output = Command::new(RSLEIGH_BIN).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Agent operations"));
    assert_eq!(
        std::fs::read_dir(&root).unwrap().count(),
        0,
        "discovery wrote files"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn invalid_invocations_report_stable_cataloged_error_codes() {
    let root = scratch();
    let binary = root.join("seed.exe");
    std::fs::write(&binary, seed::binary()).unwrap();
    let garbage = root.join("garbage.bin");
    std::fs::write(&garbage, b"not a binary").unwrap();
    let wasm = root.join("module.wasm");
    std::fs::write(&wasm, b"\0asm\x01\0\0\0").unwrap();
    let file = binary.to_str().unwrap();
    let known: Vec<String> = catalog(&root)["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["code"].as_str().unwrap().to_string())
        .collect();
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (vec![file, "--agent-brief", "--card"], "multiple_modes"),
        (
            vec![file, "--agent-brief", "--raw", "x86"],
            "unsupported_input",
        ),
        (vec![file, "--agent-brief", "--pcode"], "unsupported_option"),
        (vec![file, "--agent-brief", "extra"], "unexpected_argument"),
        (vec![file, "--agent-brief", "--limit"], "missing_value"),
        (
            vec![file, "--agent-brief", "--limit", "1", "--limit", "2"],
            "duplicate_option",
        ),
        (vec![file, "--agent-brief", "--limit", "x"], "invalid_value"),
        (vec![file, "--ssa-slice", "0x401000"], "invalid_selector"),
        (
            vec![file, "--ssa-slice", "0x401000", "--return", "--var", "1"],
            "invalid_selector",
        ),
        (
            vec![file, "0x401000", "--card", "--operation-cursor", "5"],
            "invalid_combination",
        ),
        (
            vec![file, "missing", "--card", "--json"],
            "target_not_found",
        ),
        (vec![file, "--card", "--json"], "invalid_target"),
        (
            vec![
                file,
                "0x401000",
                "--card",
                "--json",
                "--instruction-cursor",
                "9999",
            ],
            "invalid_cursor",
        ),
        (
            vec!["/nonexistent/rsleigh-input", "--agent-brief"],
            "input_unreadable",
        ),
        (
            vec![garbage.to_str().unwrap(), "--agent-brief"],
            "unsupported_format",
        ),
        (
            vec![wasm.to_str().unwrap(), "--agent-brief"],
            "unsupported_format",
        ),
        (vec!["--bogus"], "unknown_option"),
        (vec!["--capabilities", "--limit", "1"], "unsupported_option"),
    ];
    for (args, expected) in cases {
        let (code, value) = run_json(&args, &root);
        assert_eq!(code, 1, "{args:?}: {value}");
        assert_eq!(value["status"], "failed", "{args:?}");
        assert_eq!(value["error_code"], expected, "{args:?}: {value}");
        assert!(
            known.iter().any(|k| k == expected),
            "{expected} not cataloged"
        );
        // Legacy consumers still find a command diagnostic.
        assert_eq!(value["diagnostics"][0]["stage"], "command");
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn catalog_operations_and_flags_are_documented() {
    let root = scratch();
    let catalog = catalog(&root);
    let docs_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs");
    let docs: String = ["cli-reference.md", "agent-workflow.md", "output-formats.md"]
        .iter()
        .map(|name| std::fs::read_to_string(docs_dir.join(name)).unwrap())
        .collect();
    for op in catalog["operations"].as_array().unwrap() {
        let schema = op["schema"].as_str().unwrap();
        assert!(docs.contains(schema), "undocumented schema {schema}");
        let flags = std::iter::once(&op["mode"]).chain(op["flags"].as_array().unwrap());
        for flag in flags {
            let name = flag["name"].as_str().unwrap();
            assert!(
                docs.contains(name),
                "{}: undocumented flag {name}",
                op["id"]
            );
        }
    }
    for error in catalog["errors"].as_array().unwrap() {
        let code = error["code"].as_str().unwrap();
        assert!(docs.contains(code), "undocumented error code {code}");
    }
    std::fs::remove_dir_all(root).unwrap();
}

/// Catalog availability must match behavior: unsupported frontends and
/// selectors fail explicitly instead of inheriting native support.
#[test]
fn catalog_coverage_matches_frontend_and_architecture_behavior() {
    let root = scratch();
    let catalog = catalog(&root);
    for frontend in catalog["frontends"].as_array().unwrap() {
        let operations = frontend["agent_operations"].as_array().unwrap();
        match frontend["id"].as_str().unwrap() {
            "raw" | "wasm" => {
                assert!(operations.is_empty());
                assert!(frontend["reason"].is_string());
            }
            _ => assert!(!operations.is_empty()),
        }
    }
    for task in corpus::tasks() {
        let arch = catalog["architectures"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["id"] == format!("{:?}", task.architecture))
            .unwrap_or_else(|| panic!("{:?} missing from catalog", task.architecture));
        for stage in ["decode", "lift", "discovery", "decompile"] {
            assert!(matches!(
                arch["stages"][stage].as_str(),
                Some("tested" | "partial")
            ));
        }
        let binary = root.join(task.fixture);
        std::fs::write(&binary, &task.data).unwrap();
        let function = format!("0x{:x}", task.function);
        let (code, value) = run_json(
            &[
                binary.to_str().unwrap(),
                "--ssa-slice",
                &function,
                "--call-site",
                &function,
                "--arg",
                "0",
            ],
            &root,
        );
        if arch["dependency_queries"]["call_argument"] == "unsupported" {
            assert_eq!(code, 1, "{value}");
            assert_eq!(
                value["selection_error"]["code"], "unsupported_root",
                "{value}"
            );
        } else {
            assert_eq!(arch["dependency_queries"]["call_argument"], "supported");
            // Supported selectors still fail without guessing when the
            // address is not a call; the reason must not be "unsupported".
            let message = value["selection_error"]["message"].as_str().unwrap_or("");
            assert!(
                !message.contains("not yet supported for this architecture"),
                "{value}"
            );
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}
