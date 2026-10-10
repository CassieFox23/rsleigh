//! Portable evidence records and bundles: stable content IDs, offline
//! verification, round-trips, and rejection of corrupt or mixed bundles.
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

#[path = "../../test-harness/fixtures/agent-re/seed.rs"]
mod seed;

fn scratch() -> PathBuf {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "rsleigh-agent-evidence-{}-{nonce}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn rsleigh(args: &[&str], env: &[(&str, &str)]) -> (i32, Value) {
    let mut command = Command::new(RSLEIGH_BIN);
    command.args(args).env_remove("RSLEIGH_OPAQUE_FOLD");
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.output().unwrap();
    let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "{args:?}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code().unwrap(), value)
}

fn run(args: &[&str]) -> (i32, Value) {
    rsleigh(args, &[])
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

/// Rewrite one generation artifact and re-sign both manifest copies, as an
/// attacker or buggy tool could. Content-level checks must still catch it.
fn forge(bundle: &Path, name: &str, bytes: &[u8]) {
    let mut manifest: Value =
        serde_json::from_slice(&std::fs::read(bundle.join("index.json")).unwrap()).unwrap();
    let generation = manifest["generation"].as_str().unwrap().to_string();
    let directory = bundle.join("generations").join(&generation);
    std::fs::write(directory.join(name), bytes).unwrap();
    for file in manifest["files"].as_array_mut().unwrap() {
        if file["name"] == name {
            file["sha256"] = json!(sha256(bytes));
            file["size"] = json!(bytes.len());
        }
    }
    let encoded = serde_json::to_vec_pretty(&manifest).unwrap();
    std::fs::write(bundle.join("index.json"), &encoded).unwrap();
    std::fs::write(directory.join("index.json"), &encoded).unwrap();
}

fn rewrite_manifest(bundle: &Path, edit: impl FnOnce(&mut Value)) {
    let mut manifest: Value =
        serde_json::from_slice(&std::fs::read(bundle.join("index.json")).unwrap()).unwrap();
    edit(&mut manifest);
    let generation = manifest["generation"].as_str().unwrap().to_string();
    let encoded = serde_json::to_vec_pretty(&manifest).unwrap();
    std::fs::write(bundle.join("index.json"), &encoded).unwrap();
    std::fs::write(
        bundle
            .join("generations")
            .join(generation)
            .join("index.json"),
        &encoded,
    )
    .unwrap();
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
fn evidence_ids_ignore_execution_detail_and_track_semantic_inputs() {
    let root = scratch();
    let binary = root.join("seed.exe");
    std::fs::write(&binary, seed::binary()).unwrap();
    let cache = root.join("cache");
    let card = |binary: &Path, target: &str, extra: &[&str], env: &[(&str, &str)]| {
        let mut args = vec![s(binary), target, "--card", "--pcode", "--evidence"];
        args.extend(extra);
        let (code, record) = rsleigh(&args, env);
        assert_eq!(code, 0, "{record}");
        assert_eq!(record["schema"], "rsleigh.evidence/v1");
        assert_eq!(record["payload"]["schema"], "rsleigh.card/v2");
        record
    };
    let base = card(&binary, "0x401000", &[], &[]);
    let id = base["id"].as_str().unwrap();
    assert!(id.starts_with("sha256:") && id.len() == 71);
    assert_eq!(
        base["operation"]["parameters"],
        json!({"function":"0x401000","pcode":true})
    );
    assert_eq!(base["subject"]["binary_sha256"], sha256(&seed::binary()));
    assert_eq!(base["subject"]["architecture"], "X86_32");
    // Name versus address, cold versus warm cache, and another path agree.
    let cached = ["--analysis-cache", s(&cache)];
    let cold = card(&binary, "constant", &cached, &[]);
    let warm = card(&binary, "constant", &cached, &[]);
    assert_eq!(cold["payload"]["metrics"]["cache"], "miss");
    assert_eq!(warm["payload"]["metrics"]["cache"], "hit");
    let moved = root.join("elsewhere").join("renamed.bin");
    std::fs::create_dir_all(moved.parent().unwrap()).unwrap();
    std::fs::copy(&binary, &moved).unwrap();
    for other in [&cold, &warm, &card(&moved, "0x401000", &[], &[])] {
        assert_eq!(other["id"], base["id"], "{other}");
    }
    // Pages, binary content, and analysis profile are part of the identity.
    let page = card(&binary, "0x401000", &["--instruction-cursor", "1"], &[]);
    assert_ne!(page["id"], base["id"]);
    assert_ne!(
        page["coverage"]["instructions"],
        base["coverage"]["instructions"]
    );
    let opaque = card(&binary, "0x401000", &[], &[("RSLEIGH_OPAQUE_FOLD", "1")]);
    assert_ne!(opaque["id"], base["id"]);
    std::fs::write(binary.with_extension("pdb"), b"companion input").unwrap();
    assert_ne!(card(&binary, "0x401000", &[], &[])["id"], base["id"]);
    std::fs::remove_file(binary.with_extension("pdb")).unwrap();
    let mut changed = seed::binary();
    changed[0x201] = 8; // mov eax, 8
    std::fs::write(&binary, &changed).unwrap();
    assert_ne!(card(&binary, "0x401000", &[], &[])["id"], base["id"]);
    std::fs::remove_dir_all(root).unwrap();
}

/// Store a few records, export, move, verify, import, and re-export.
#[test]
fn bundles_move_verify_and_round_trip_partial_records() {
    let root = scratch();
    let binary = root.join("seed.exe");
    std::fs::write(&binary, seed::binary()).unwrap();
    let store = root.join("store");
    let file = s(&binary);
    let (code, card) = run(&[
        file,
        "0x401000",
        "--card",
        "--pcode",
        "--evidence-store",
        s(&store),
    ]);
    assert_eq!(code, 0, "{card}");
    let (code, slice) = run(&[
        file,
        "--ssa-slice",
        "0x401060",
        "--return",
        "--evidence-store",
        s(&store),
        "--derived-from",
        card["id"].as_str().unwrap(),
    ]);
    assert_eq!(code, 2, "{slice}");
    assert_eq!(slice["status"], "partial");
    assert_eq!(slice["coverage"]["complete"], false);
    assert_eq!(slice["coverage"]["boundaries"]["unmodeled_memory"], 1);
    assert_eq!(slice["references"], json!([card["id"]]));
    let (code, page) = run(&[
        file,
        "0x401000",
        "--card",
        "--evidence-store",
        s(&store),
        "--instruction-cursor",
        "1",
    ]);
    assert_eq!(code, 0);
    assert_eq!(
        page["coverage"]["complete"], false,
        "a later page is not the whole function"
    );

    // Selecting the slice pulls in the card it was derived from.
    let bundle = root.join("bundle");
    let (code, manifest) = run(&[
        file,
        "--export-bundle",
        s(&bundle),
        "--evidence-store",
        s(&store),
        "--record",
        slice["id"].as_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{manifest}");
    assert_eq!(manifest["schema"], "rsleigh.evidence-bundle/v1");
    let ids: Vec<&str> = manifest["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&card["id"].as_str().unwrap()));
    assert_eq!(manifest["coverage"]["partial"], 1);

    let moved = root.join("moved").join("handoff");
    std::fs::create_dir_all(moved.parent().unwrap()).unwrap();
    std::fs::rename(&bundle, &moved).unwrap();
    let (code, integrity) = run(&["--verify-bundle", s(&moved)]);
    assert_eq!(code, 2, "{integrity}");
    assert_eq!(integrity["status"], "partial");
    assert_eq!(integrity["checks"]["source_binding"], "not_checked");
    assert!(integrity["verified_scope"]
        .as_str()
        .unwrap()
        .contains("integrity only"));
    let (code, bound) = run(&[file, "--verify-bundle", s(&moved)]);
    assert_eq!(code, 0, "{bound}");
    assert_eq!(bound["checks"]["source_binding"], "verified");
    assert_eq!(bound["records"]["partial"], 1);

    // Import into a fresh store, then re-export: IDs and statuses survive.
    let imported = root.join("imported");
    let (code, report) = run(&[
        "--import-bundle",
        s(&moved),
        "--evidence-store",
        s(&imported),
    ]);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["records"]["imported"], 2);
    let (_, again) = run(&[
        "--import-bundle",
        s(&moved),
        "--evidence-store",
        s(&imported),
    ]);
    assert_eq!(again["records"]["existing"], 2);
    let reexport = root.join("reexport");
    let (code, second) = run(&[
        file,
        "--export-bundle",
        s(&reexport),
        "--evidence-store",
        s(&imported),
    ]);
    assert_eq!(code, 0, "{second}");
    assert_eq!(second["records"], manifest["records"]);
    let stored: Value = serde_json::from_slice(
        &std::fs::read(imported.join("records").join(format!(
            "{}.json",
            slice["id"].as_str().unwrap().trim_start_matches("sha256:")
        )))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(stored["status"], "partial");
    assert_eq!(stored["payload"]["slice"]["complete"], false);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn corrupt_incomplete_mixed_and_forged_bundles_never_verify() {
    let root = scratch();
    let binary = root.join("seed.exe");
    std::fs::write(&binary, seed::binary()).unwrap();
    let other = root.join("other.exe");
    let mut other_bytes = seed::binary();
    other_bytes[0x201] = 9;
    std::fs::write(&other, &other_bytes).unwrap();
    let store = root.join("store");
    for (file, function) in [
        (&binary, "0x401000"),
        (&binary, "0x401080"),
        (&other, "0x401000"),
    ] {
        let (code, record) = run(&[s(file), function, "--card", "--evidence-store", s(&store)]);
        assert_eq!(code, 0, "{record}");
    }
    let bundle = root.join("bundle");
    let (code, manifest) = run(&[
        s(&binary),
        "--export-bundle",
        s(&bundle),
        "--evidence-store",
        s(&store),
    ]);
    assert_eq!(code, 0, "{manifest}");
    assert_eq!(
        manifest["records"].as_array().unwrap().len(),
        2,
        "only this binary's records"
    );
    let names: Vec<String> = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap().to_string())
        .collect();
    let artifact = |dir: &Path, name: &str| {
        let manifest: Value =
            serde_json::from_slice(&std::fs::read(dir.join("index.json")).unwrap()).unwrap();
        dir.join("generations")
            .join(manifest["generation"].as_str().unwrap())
            .join(name)
    };
    let expect_failure = |dir: &Path, needle: &str| {
        let (code, value) = run(&["--verify-bundle", s(dir)]);
        assert_eq!(code, 1, "{value}");
        assert_eq!(value["error_code"], "verification_failed", "{value}");
        assert!(
            value["error"].as_str().unwrap().contains(needle),
            "{needle}: {value}"
        );
    };
    let variant = |label: &str| {
        let copy = root.join(label);
        copy_dir(&bundle, &copy);
        copy
    };

    let corrupt = variant("corrupt");
    std::fs::write(artifact(&corrupt, &names[0]), b"corrupt").unwrap();
    expect_failure(&corrupt, "checksum");

    let missing = variant("missing");
    std::fs::remove_file(artifact(&missing, &names[1])).unwrap();
    expect_failure(&missing, "cannot read");

    let malformed = variant("malformed");
    std::fs::write(malformed.join("index.json"), b"{not json").unwrap();
    expect_failure(&malformed, "invalid index manifest");

    // Re-signed checksums cannot launder an edited record: its content ID,
    // derived coverage, and subject are recomputed from the payload.
    let edited = variant("edited");
    let mut record: Value =
        serde_json::from_slice(&std::fs::read(artifact(&edited, &names[0])).unwrap()).unwrap();
    // Toggle rather than set: record IDs include the producer build, so which
    // record sorts first (and whether it is complete) varies across builds.
    let complete = record["coverage"]["complete"] == true;
    record["coverage"]["complete"] = json!(!complete);
    forge(
        &edited,
        &names[0],
        &serde_json::to_vec_pretty(&record).unwrap(),
    );
    expect_failure(&edited, "content ID");

    let mixed = variant("mixed");
    let (_, other_record) = run(&[s(&other), "0x401000", "--card", "--evidence"]);
    let other_id = other_record["id"].as_str().unwrap();
    let other_name = format!("record-{}.json", other_id.trim_start_matches("sha256:"));
    std::fs::write(
        artifact(&mixed, &other_name),
        serde_json::to_vec_pretty(&other_record).unwrap(),
    )
    .unwrap();
    let other_bytes = std::fs::read(artifact(&mixed, &other_name)).unwrap();
    rewrite_manifest(&mixed, |m| {
        let generation = m["generation"].as_str().unwrap().to_string();
        m["files"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name":other_name,
            "path":format!("generations/{generation}/{other_name}"),
            "sha256":sha256(&other_bytes),"size":other_bytes.len()}));
        m["records"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":other_id,"kind":"card",
            "status":"ok","file":other_name,"references":[]}));
        m["coverage"]["records"] = json!(3);
        m["coverage"]["ok"] = json!(3);
        m["coverage"]["complete"] = json!(3);
    });
    expect_failure(&mixed, "different targets");

    // Dropping a record from the manifest leaves its file undeclared.
    let undeclared = variant("undeclared");
    let kept = manifest["records"][0]["file"].as_str().unwrap();
    let kept: Value =
        serde_json::from_slice(&std::fs::read(artifact(&undeclared, kept)).unwrap()).unwrap();
    rewrite_manifest(&undeclared, |m| {
        m["records"].as_array_mut().unwrap().truncate(1);
        m["coverage"] = json!({"records":1,"ok":1,"partial":0,"failed":0,
            "complete":u8::from(kept["coverage"]["complete"] == true)});
    });
    expect_failure(&undeclared, "undeclared bundle artifact");

    let (code, wrong) = run(&[s(&other), "--verify-bundle", s(&bundle)]);
    assert_eq!(code, 1);
    assert!(wrong["error"].as_str().unwrap().contains("does not match"));
    // The intact original still verifies.
    assert_eq!(run(&[s(&binary), "--verify-bundle", s(&bundle)]).0, 0);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn derived_links_require_available_same_target_evidence() {
    let root = scratch();
    let binary = root.join("seed.exe");
    std::fs::write(&binary, seed::binary()).unwrap();
    let other = root.join("other.exe");
    let mut changed = seed::binary();
    changed[0x201] = 9;
    std::fs::write(&other, changed).unwrap();
    let store = root.join("store");
    let file = s(&binary);
    let (_, card) = run(&[file, "0x401000", "--card", "--evidence-store", s(&store)]);
    let (_, foreign) = run(&[
        s(&other),
        "0x401000",
        "--card",
        "--evidence-store",
        s(&store),
    ]);
    let card_id = card["id"].as_str().unwrap();
    let absent = format!("sha256:{}", "0".repeat(64));
    for (args, code) in [
        (
            vec![
                file,
                "--ssa-slice",
                "0x401000",
                "--return",
                "--evidence",
                "--derived-from",
                card_id,
            ],
            "invalid_combination",
        ),
        (
            vec![
                file,
                "--ssa-slice",
                "0x401000",
                "--return",
                "--evidence-store",
                s(&store),
                "--derived-from",
                &absent,
            ],
            "missing_evidence",
        ),
        (
            vec![
                file,
                "--ssa-slice",
                "0x401000",
                "--return",
                "--evidence-store",
                s(&store),
                "--derived-from",
                foreign["id"].as_str().unwrap(),
            ],
            "invalid_combination",
        ),
        (
            vec![
                file,
                "--ssa-slice",
                "0x401000",
                "--return",
                "--evidence-store",
                s(&store),
                "--derived-from",
                "card-1",
            ],
            "invalid_value",
        ),
    ] {
        let (exit, value) = run(&args);
        assert_eq!(exit, 1, "{value}");
        assert_eq!(value["error_code"], code, "{value}");
    }
    let (code, linked) = run(&[
        file,
        "--ssa-slice",
        "0x401000",
        "--return",
        "--evidence-store",
        s(&store),
        "--derived-from",
        card_id,
        "--derived-from",
        card_id,
    ]);
    assert_eq!(code, 0, "{linked}");
    assert_eq!(linked["references"], json!([card_id]));
    // An export whose dependency has disappeared fails instead of dropping it.
    std::fs::remove_file(
        store
            .join("records")
            .join(format!("{}.json", card_id.trim_start_matches("sha256:"))),
    )
    .unwrap();
    let (code, value) = run(&[
        file,
        "--export-bundle",
        s(&root.join("bundle")),
        "--evidence-store",
        s(&store),
        "--record",
        linked["id"].as_str().unwrap(),
    ]);
    assert_eq!(code, 1);
    assert_eq!(value["error_code"], "missing_evidence", "{value}");
    assert!(!root.join("bundle").join("index.json").exists());
    std::fs::remove_dir_all(root).unwrap();
}
