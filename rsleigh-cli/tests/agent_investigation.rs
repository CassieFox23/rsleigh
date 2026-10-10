//! Durable investigations: reopening without rediscovery, revision checks,
//! evidence-checked answers, and unknowns that survive handoff.
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

#[path = "../../test-harness/fixtures/agent-re/seed.rs"]
mod seed;
use seed as re_seed;
#[path = "../../test-harness/fixtures/agent-re/variants.rs"]
mod variants;

fn scratch() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "rsleigh-agent-investigation-{}-{nonce}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn output(args: &[&str]) -> (i32, Vec<u8>) {
    let out = Command::new(RSLEIGH_BIN)
        .args(args)
        .env_remove("RSLEIGH_OPAQUE_FOLD")
        .output()
        .unwrap();
    (out.status.code().unwrap(), out.stdout)
}

fn run(args: &[&str]) -> (i32, Value) {
    let (code, stdout) = output(args);
    let value = serde_json::from_slice(&stdout)
        .unwrap_or_else(|_| panic!("{args:?}: {}", String::from_utf8_lossy(&stdout)));
    (code, value)
}

fn ok(args: &[&str]) -> Value {
    let (code, value) = run(args);
    assert!(matches!(code, 0 | 2), "{args:?}: {value}");
    value
}

fn fail(args: &[&str], error_code: &str) -> Value {
    let (code, value) = run(args);
    assert_eq!(code, 1, "{args:?}: {value}");
    assert_eq!(value["error_code"], error_code, "{args:?}: {value}");
    value
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn issue<'a>(view: &'a Value, id: &str) -> &'a Value {
    view["investigation"]["issues"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == id)
        .unwrap_or_else(|| panic!("no issue {id}: {view}"))
}

#[test]
fn reopened_investigation_shows_pending_question_without_the_binary() {
    let root = scratch();
    let binary = root.join("seed.exe");
    std::fs::write(&binary, seed::binary()).unwrap();
    let inv = root.join("inv");
    let created = ok(&[
        s(&binary),
        "--investigate",
        s(&inv),
        "--question",
        "What does constant return?",
        "--require",
        "ssa-slice",
    ]);
    assert_eq!(created["schema"], "rsleigh.investigation-view/v1");
    assert_eq!(created["investigation"]["revision"], 1);
    let question = created["pending"][0]["id"].as_str().unwrap().to_string();
    // Reopening needs neither the binary nor any discovery.
    std::fs::remove_file(&binary).unwrap();
    let (code, reopened) = run(&["--investigation", s(&inv)]);
    assert_eq!(code, 0, "{reopened}");
    assert_eq!(reopened["pending"][0]["id"], question.as_str());
    assert_eq!(reopened["pending"][0]["text"], "What does constant return?");
    assert_eq!(
        reopened["investigation"]["target"]["binary_sha256"],
        created["investigation"]["target"]["binary_sha256"]
    );
    let next = &reopened["next_queries"][0];
    assert_eq!(next["issue"], question.as_str());
    assert_eq!(next["argv"][0], "FILE");
    assert!(next["command"].as_str().unwrap().starts_with("rsleigh '"));
    // Creation never overwrites an existing investigation.
    std::fs::write(&binary, seed::binary()).unwrap();
    fail(
        &[s(&binary), "--investigate", s(&inv), "--question", "again"],
        "stale_revision",
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn revision_checks_reject_stale_updates_and_preserve_history() {
    let root = scratch();
    let binary = root.join("seed.exe");
    std::fs::write(&binary, seed::binary()).unwrap();
    let inv = root.join("inv");
    ok(&[s(&binary), "--investigate", s(&inv), "--question", "q"]);
    let first = std::fs::read(inv.join("revisions/000001.json")).unwrap();
    fail(
        &["--investigation", s(&inv), "--add-question", "unchecked"],
        "invalid_combination",
    );
    let updated = ok(&[
        "--investigation",
        s(&inv),
        "--expect-revision",
        "1",
        "--add-question",
        "second",
    ]);
    assert_eq!(updated["investigation"]["revision"], 2);
    assert_eq!(updated["change"]["revision"], 2);
    // A writer that loaded revision 1 cannot overwrite revision 2.
    fail(
        &[
            "--investigation",
            s(&inv),
            "--expect-revision",
            "1",
            "--add-question",
            "lost",
        ],
        "stale_revision",
    );
    fail(
        &[
            "--investigation",
            s(&inv),
            "--expect-revision",
            "2",
            "--add-question",
            "a",
            "--observe",
            "b",
        ],
        "invalid_combination",
    );
    fail(
        &[
            "--investigation",
            s(&inv),
            "--expect-revision",
            "2",
            "--add-question",
            "second",
        ],
        "invalid_value",
    );
    assert_eq!(
        std::fs::read(inv.join("revisions/000001.json")).unwrap(),
        first
    );
    let mirror: Value =
        serde_json::from_slice(&std::fs::read(inv.join("investigation.json")).unwrap()).unwrap();
    assert_eq!(mirror["revision"], 2);
    assert_eq!(mirror["history"].as_array().unwrap().len(), 2);
    // Binding to the wrong binary is rejected.
    let other = root.join("other.exe");
    let mut changed = seed::binary();
    changed[0x201] = 9;
    std::fs::write(&other, changed).unwrap();
    fail(
        &[s(&other), "--investigation", s(&inv)],
        "verification_failed",
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn answers_require_available_evidence_and_withdrawal_is_not_an_answer() {
    let root = scratch();
    let binary = root.join("seed.exe");
    std::fs::write(&binary, seed::binary()).unwrap();
    let inv = root.join("inv");
    let file = s(&binary);
    let view = ok(&[
        file,
        "--investigate",
        s(&inv),
        "--question",
        "What does constant return?",
        "--require",
        "ssa-slice",
    ]);
    let question = view["pending"][0]["id"].as_str().unwrap().to_string();
    let card = ok(&[
        file,
        "0x401000",
        "--card",
        "--pcode",
        "--evidence-store",
        s(&inv),
    ]);
    let slice = ok(&[
        file,
        "--ssa-slice",
        "0x401000",
        "--return",
        "--evidence-store",
        s(&inv),
    ]);
    let (card_id, slice_id) = (card["id"].as_str().unwrap(), slice["id"].as_str().unwrap());
    let absent = format!("sha256:{}", "0".repeat(64));
    fail(
        &[
            "--investigation",
            s(&inv),
            "--expect-revision",
            "1",
            "--resolve",
            &question,
            "--disposition",
            "answered",
        ],
        "requirements_unmet",
    );
    fail(
        &[
            "--investigation",
            s(&inv),
            "--expect-revision",
            "1",
            "--resolve",
            &question,
            "--disposition",
            "answered",
            "--cite",
            &absent,
        ],
        "missing_evidence",
    );
    fail(
        &[
            "--investigation",
            s(&inv),
            "--expect-revision",
            "1",
            "--resolve",
            &question,
            "--disposition",
            "answered",
            "--cite",
            card_id,
        ],
        "requirements_unmet",
    );
    // Supporting evidence that later disappears cannot close the question.
    ok(&[
        "--investigation",
        s(&inv),
        "--expect-revision",
        "1",
        "--support",
        &question,
        "--cite",
        slice_id,
    ]);
    let slice_file = inv
        .join("records")
        .join(format!("{}.json", slice_id.trim_start_matches("sha256:")));
    let saved = std::fs::read(&slice_file).unwrap();
    std::fs::remove_file(&slice_file).unwrap();
    fail(
        &[
            "--investigation",
            s(&inv),
            "--expect-revision",
            "2",
            "--resolve",
            &question,
            "--disposition",
            "answered",
        ],
        "missing_evidence",
    );
    std::fs::write(&slice_file, saved).unwrap();
    let answered = ok(&[
        "--investigation",
        s(&inv),
        "--expect-revision",
        "2",
        "--resolve",
        &question,
        "--disposition",
        "answered",
        "--note",
        "returns 7",
    ]);
    let resolved = issue(&answered, &question);
    assert_eq!(resolved["state"], "answered");
    assert_eq!(
        resolved["resolution"]["validation"],
        "references_and_requirements_checked"
    );
    assert_eq!(
        resolved["resolution"]["evidence"],
        serde_json::json!([slice_id])
    );
    fail(
        &[
            "--investigation",
            s(&inv),
            "--expect-revision",
            "3",
            "--resolve",
            &question,
            "--disposition",
            "withdrawn",
        ],
        "invalid_combination",
    );
    let added = ok(&[
        "--investigation",
        s(&inv),
        "--expect-revision",
        "3",
        "--add-question",
        "Is it pure?",
    ]);
    let second = added["pending"][0]["id"].as_str().unwrap().to_string();
    let withdrawn = ok(&[
        "--investigation",
        s(&inv),
        "--expect-revision",
        "4",
        "--resolve",
        &second,
        "--disposition",
        "withdrawn",
        "--note",
        "out of time",
    ]);
    assert_eq!(issue(&withdrawn, &second)["state"], "withdrawn");
    assert_eq!(
        issue(&withdrawn, &second)["resolution"]["validation"],
        "analyst_disposition_only"
    );
    assert_eq!(withdrawn["summary"]["verified_answers"], 1);
    assert_eq!(withdrawn["summary"]["withdrawn"], 1);
    fail(
        &[
            "--investigation",
            s(&inv),
            "--expect-revision",
            "5",
            "--observe",
            "no evidence",
        ],
        "invalid_combination",
    );
    let observed = ok(&[
        "--investigation",
        s(&inv),
        "--expect-revision",
        "5",
        "--observe",
        "constant 7",
        "--cite",
        slice_id,
    ]);
    assert_eq!(
        observed["investigation"]["observations"][0]["evidence"][0],
        slice_id
    );
    let inferred = ok(&[
        "--investigation",
        s(&inv),
        "--expect-revision",
        "6",
        "--infer",
        "probably a getter",
    ]);
    assert_eq!(
        inferred["investigation"]["inferences"][0]["assessment"],
        "provisional"
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn unresolved_indirect_call_and_contradictions_survive_handoff() {
    let root = scratch();
    let binary = root.join("indirect.exe");
    std::fs::write(&binary, variants::indirect_call()).unwrap();
    let inv = root.join("inv");
    let file = s(&binary);
    ok(&[
        file,
        "--investigate",
        s(&inv),
        "--question",
        "What does load return?",
    ]);
    let slice = ok(&[
        file,
        "--ssa-slice",
        "0x401060",
        "--return",
        "--evidence-store",
        s(&inv),
    ]);
    assert_eq!(
        slice["coverage"]["boundaries"]["unknown_call"], 1,
        "{slice}"
    );
    let slice_id = slice["id"].as_str().unwrap();
    let added = ok(&[
        "--investigation",
        s(&inv),
        "--expect-revision",
        "1",
        "--add-unknowns",
        slice_id,
    ]);
    let unknown = added["change"]["added"][0].as_str().unwrap().to_string();
    assert!(unknown.starts_with("u-"));
    assert_eq!(
        issue(&added, &unknown)["location"]["call"]["resolution"],
        "unresolved_indirect"
    );
    // Rerunning with different traversal limits reaches the same unknown.
    let rerun = ok(&[
        file,
        "--ssa-slice",
        "0x401060",
        "--return",
        "--max-nodes",
        "8",
        "--evidence-store",
        s(&inv),
    ]);
    assert_ne!(rerun["id"], slice["id"]);
    fail(
        &[
            "--investigation",
            s(&inv),
            "--expect-revision",
            "2",
            "--add-unknowns",
            rerun["id"].as_str().unwrap(),
        ],
        "invalid_value",
    );
    let next: Vec<&Value> = added["next_queries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|q| q["issue"] == unknown.as_str())
        .collect();
    assert_eq!(next.len(), 1);
    assert_eq!(next[0]["operation"], "card");
    assert_eq!(next[0]["argv"][1], "0x401060");

    let card = ok(&[
        file,
        "0x401060",
        "--card",
        "--pcode",
        "--evidence-store",
        s(&inv),
    ]);
    let card_id = card["id"].as_str().unwrap();
    ok(&[
        "--investigation",
        s(&inv),
        "--expect-revision",
        "2",
        "--support",
        &unknown,
        "--cite",
        card_id,
    ]);
    ok(&[
        "--investigation",
        s(&inv),
        "--expect-revision",
        "3",
        "--contradict",
        &unknown,
        "--cite",
        rerun["id"].as_str().unwrap(),
    ]);

    let bundle = root.join("bundle");
    let manifest = ok(&[
        file,
        "--export-bundle",
        s(&bundle),
        "--investigation",
        s(&inv),
    ]);
    assert_eq!(manifest["investigation"]["revision"], 4);
    assert_eq!(manifest["coverage"]["records"], 3);
    assert_eq!(run(&[file, "--verify-bundle", s(&bundle)]).0, 0);
    let imported = root.join("imported");
    let report = ok(&[
        "--import-bundle",
        s(&bundle),
        "--investigation",
        s(&imported),
    ]);
    assert_eq!(report["investigation"]["imported"], true);
    fail(
        &[
            "--import-bundle",
            s(&bundle),
            "--investigation",
            s(&imported),
        ],
        "stale_revision",
    );
    std::fs::remove_file(&binary).unwrap();
    let (code, view) = run(&["--investigation", s(&imported)]);
    assert_eq!(code, 0, "{view}");
    let survived = issue(&view, &unknown);
    assert_eq!(survived["state"], "open");
    assert_eq!(survived["supporting"], serde_json::json!([card_id]));
    assert_eq!(survived["contradicting"], serde_json::json!([rerun["id"]]));
    assert!(view["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["available"] == true));
    assert_eq!(
        view["investigation"]["history"].as_array().unwrap().len(),
        4
    );
    let (code, markdown) = output(&["--investigation", s(&imported), "--handoff"]);
    assert_eq!(code, 0);
    let markdown = String::from_utf8(markdown).unwrap();
    let unresolved =
        &markdown[markdown.find("## Unresolved").unwrap()..markdown.find("## Closed").unwrap()];
    assert!(
        unresolved.contains(&unknown) && unresolved.contains("unknown_call"),
        "{markdown}"
    );
    assert!(
        unresolved.contains(&format!("contradicting: {}", rerun["id"].as_str().unwrap())),
        "{markdown}"
    );
    // Tampered investigation attachments fail bundle verification.
    let generation = manifest["generation"].as_str().unwrap();
    let doc = bundle
        .join("generations")
        .join(generation)
        .join("investigation.json");
    let mut tampered: Value = serde_json::from_slice(&std::fs::read(&doc).unwrap()).unwrap();
    tampered["issues"][1]["state"] = serde_json::json!("withdrawn");
    std::fs::write(&doc, serde_json::to_vec_pretty(&tampered).unwrap()).unwrap();
    assert_eq!(run(&["--verify-bundle", s(&bundle)]).0, 1);
    std::fs::remove_dir_all(root).unwrap();
}
