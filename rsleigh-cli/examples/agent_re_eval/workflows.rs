//! Workflow tasks for capability discovery, evidence handoff, investigations,
//! and function comparison; called by agent_re_eval --workflows. Each task
//! records answer and evidence correctness, commands, returned bytes, elapsed
//! time, cache work, and artifact size. Lost references and incorrect
//! upgrades from partial/unknown to complete/answered/unchanged must be zero.
//! A task whose expected answer is "unknown" passes when the unknown is
//! retained.
use super::{corpus, directory_bytes, seed, variants};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

struct Session<'a> {
    tool: &'a Path,
    root: PathBuf,
    commands: Vec<Value>,
}

impl Session<'_> {
    fn exec(&mut self, argv: &[&str]) -> (i32, Vec<u8>) {
        let start = Instant::now();
        let output = Command::new(self.tool)
            .args(argv)
            .env_remove("RSLEIGH_OPAQUE_FOLD")
            .output()
            .expect("start CLI");
        let code = output.status.code().unwrap_or(-1);
        let schema = serde_json::from_slice::<Value>(&output.stdout)
            .map(|v| v["schema"].clone())
            .unwrap_or(Value::Null);
        self.commands.push(json!({"argv":argv,"exit_code":code,
            "elapsed_us":start.elapsed().as_micros() as u64,
            "stdout_bytes":output.stdout.len(),"schema":schema}));
        (code, output.stdout)
    }

    fn run(&mut self, argv: &[&str]) -> (i32, Value) {
        let (code, stdout) = self.exec(argv);
        (code, serde_json::from_slice(&stdout).unwrap_or(Value::Null))
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn dir(&self, name: &str) -> (PathBuf, String) {
        let path = self.root.join(name);
        let text = text(&path);
        (path, text)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.path(name);
        std::fs::write(&path, bytes).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn total(&self, key: &str) -> u64 {
        self.commands
            .iter()
            .map(|c| c[key].as_u64().unwrap_or(0))
            .sum()
    }
}

struct Outcome {
    answer: bool,
    evidence: bool,
    lost_references: u64,
    incorrect_upgrades: u64,
    artifact_bytes: u64,
    details: Value,
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn root_constant(slice: &Value) -> Option<u64> {
    let root = slice["slice"]["root"].as_u64()?;
    slice["slice"]["nodes"]
        .as_array()?
        .iter()
        .find(|n| n["var_id"] == root && n["context_id"] == 0)?["constant"]
        .as_u64()
}

fn record_file(store: &Path, id: &str) -> Value {
    let path = store
        .join("records")
        .join(format!("{}.json", id.trim_start_matches("sha256:")));
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null)
}

fn capability_guided_selection(s: &mut Session) -> Outcome {
    let (code, catalog) = s.run(&["--capabilities", "--json"]);
    let task = corpus::tasks()
        .into_iter()
        .find(|t| t.id == "mips-return")
        .unwrap();
    let mips = s.write("return-mips.elf", &task.data);
    let support = catalog["architectures"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["id"] == "MIPS32")
        .map(|a| a["dependency_queries"].clone())
        .unwrap_or(Value::Null);
    let unsupported = support["call_argument"] == "unsupported" && support["return"] == "supported";
    // Following the catalog, the agent uses the supported return selector.
    let (exit, slice) = s.run(&[
        &mips,
        "--ssa-slice",
        "0x401000",
        "--return",
        "--at",
        "0x401004",
    ]);
    // Consistency: the advertised-unsupported selector is rejected explicitly.
    let (rejected_code, rejected) = s.run(&[
        &mips,
        "--ssa-slice",
        "0x401000",
        "--call-site",
        "0x401000",
        "--arg",
        "0",
    ]);
    Outcome {
        answer: code == 0
            && unsupported
            && matches!(exit, 0 | 2)
            && root_constant(&slice) == Some(42),
        evidence: slice["file_sha256"] == sha(&task.data)
            && rejected_code == 1
            && rejected["selection_error"]["code"] == "unsupported_root"
            && catalog["frontends"].as_array().is_some_and(|f| {
                f.iter().any(|f| {
                    f["id"] == "raw" && f["agent_operations"].as_array().is_some_and(Vec::is_empty)
                })
            }),
        lost_references: 0,
        incorrect_upgrades: u64::from(rejected_code != 1),
        artifact_bytes: 0,
        details: json!({"mips32_dependency_queries":support}),
    }
}

fn portable_handoff(s: &mut Session) -> Outcome {
    let data = seed::binary();
    let file = s.write("seed.exe", &data);
    let ((_, store_s), (_, cache_s), (bundle, bundle_s)) =
        (s.dir("store"), s.dir("cache"), s.dir("bundle"));
    let slice_args = [
        file.as_str(),
        "--ssa-slice",
        "0x401000",
        "--return",
        "--analysis-cache",
        &cache_s,
        "--evidence-store",
        &store_s,
    ];
    let (_, cold) = s.run(&slice_args);
    let (_, warm) = s.run(&slice_args);
    let slice_id = cold["id"].as_str().unwrap_or("").to_string();
    let (_, card) = s.run(&[
        &file,
        "0x401000",
        "--card",
        "--pcode",
        "--evidence-store",
        &store_s,
        "--derived-from",
        &slice_id,
    ]);
    let (export_code, manifest) = s.run(&[
        &file,
        "--export-bundle",
        &bundle_s,
        "--evidence-store",
        &store_s,
    ]);
    let (moved, moved_s) = s.dir("moved-bundle");
    std::fs::rename(&bundle, &moved).unwrap();
    let (integrity_code, _) = s.run(&["--verify-bundle", &moved_s]);
    let (bound_code, bound) = s.run(&[&file, "--verify-bundle", &moved_s]);
    let (imported, imported_s) = s.dir("imported");
    let (import_code, _) = s.run(&["--import-bundle", &moved_s, "--evidence-store", &imported_s]);
    let (_, reexport_s) = s.dir("reexport");
    let (_, reexport) = s.run(&[
        &file,
        "--export-bundle",
        &reexport_s,
        "--evidence-store",
        &imported_s,
    ]);
    let copy = record_file(&imported, &slice_id);
    let card_copy = record_file(&imported, card["id"].as_str().unwrap_or(""));
    let mut lost = 0;
    for entry in manifest["records"].as_array().into_iter().flatten() {
        for reference in entry["references"].as_array().into_iter().flatten() {
            lost += u64::from(record_file(&imported, reference.as_str().unwrap_or("")).is_null());
        }
        lost += u64::from(record_file(&imported, entry["id"].as_str().unwrap_or("")).is_null());
    }
    let upgrades = manifest["records"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| record_file(&imported, e["id"].as_str().unwrap_or(""))["status"] != e["status"])
        .count() as u64;
    Outcome {
        answer: root_constant(&copy["payload"]) == Some(7),
        evidence: cold["id"] == warm["id"]
            && warm["payload"]["metrics"]["cache"] == "hit"
            && export_code == 0
            && integrity_code == 2
            && bound_code == 0
            && bound["checks"]["source_binding"] == "verified"
            && import_code == 0
            && reexport["records"] == manifest["records"]
            && card_copy["references"] == json!([slice_id]),
        lost_references: lost,
        incorrect_upgrades: upgrades,
        artifact_bytes: directory_bytes(&moved),
        details: json!({"cache":{"cold":cold["payload"]["metrics"]["cache"],"warm":warm["payload"]["metrics"]["cache"],
            "warm_ssa_builds":warm["payload"]["metrics"]["ssa_builds"],"warm_decode_builds":warm["payload"]["metrics"]["decode_builds"]},
            "records":manifest["coverage"]}),
    }
}

fn unresolved_question_retention(s: &mut Session) -> Outcome {
    let data = variants::indirect_call();
    let file = s.write("indirect.exe", &data);
    let ((_, inv), (bundle, bundle_s), (_, copy)) =
        (s.dir("inv"), s.dir("bundle"), s.dir("inv-copy"));
    s.run(&[
        &file,
        "--investigate",
        &inv,
        "--question",
        "What does load return?",
    ]);
    let (_, slice) = s.run(&[
        &file,
        "--ssa-slice",
        "0x401060",
        "--return",
        "--evidence-store",
        &inv,
    ]);
    let slice_id = slice["id"].as_str().unwrap_or("").to_string();
    let (_, added) = s.run(&[
        "--investigation",
        &inv,
        "--expect-revision",
        "1",
        "--add-unknowns",
        &slice_id,
    ]);
    let unknown = added["change"]["added"][0]
        .as_str()
        .unwrap_or("")
        .to_string();
    let (export_code, _) = s.run(&[&file, "--export-bundle", &bundle_s, "--investigation", &inv]);
    let (import_code, _) = s.run(&["--import-bundle", &bundle_s, "--investigation", &copy]);
    // Resume in a fresh session without the binary: no rediscovery possible.
    std::fs::remove_file(&file).unwrap();
    let reopen_from = s.commands.len();
    let (_, view) = s.run(&["--investigation", &copy]);
    let (_, markdown) = s.exec(&["--investigation", &copy, "--handoff"]);
    let resume: Vec<Value> = s.commands[reopen_from..].to_vec();
    let markdown = String::from_utf8_lossy(&markdown);
    let issue = view["investigation"]["issues"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|i| i["id"] == unknown.as_str())
        .cloned()
        .unwrap_or(Value::Null);
    let unresolved = markdown
        .split("## Closed")
        .next()
        .is_some_and(|section| section.contains(&unknown) && section.contains("unknown_call"));
    // Baseline: the pre-investigation workflow re-derives the same state.
    std::fs::write(&file, &data).unwrap();
    let baseline_from = s.commands.len();
    s.run(&[&file, "--agent-brief", "--limit", "5"]);
    s.run(&[&file, "--ssa-slice", "0x401060", "--return"]);
    let baseline: Vec<Value> = s.commands[baseline_from..].to_vec();
    let measure = |commands: &[Value]| {
        json!({"commands":commands.len(),
            "stdout_bytes":commands.iter().map(|c| c["stdout_bytes"].as_u64().unwrap_or(0)).sum::<u64>(),
            "elapsed_us":commands.iter().map(|c| c["elapsed_us"].as_u64().unwrap_or(0)).sum::<u64>()})
    };
    let lost = view["evidence"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["available"] != true)
        .count() as u64;
    Outcome {
        answer: issue["state"] == "open"
            && issue["key"]["reason"] == "unknown_call"
            && view["pending"].as_array().is_some_and(|p| p.len() == 2),
        evidence: export_code == 0
            && import_code == 0
            && unresolved
            && issue["location"]["call"]["resolution"] == "unresolved_indirect"
            && view["next_queries"].as_array().is_some_and(|q| {
                q.iter()
                    .any(|q| q["issue"] == unknown.as_str() && q["argv"][1] == "0x401060")
            }),
        lost_references: lost,
        incorrect_upgrades: u64::from(issue["state"] != "open"),
        artifact_bytes: directory_bytes(&bundle),
        details: json!({"resume_without_binary":measure(&resume),"baseline_rediscovery":measure(&baseline)}),
    }
}

fn contradiction_preservation(s: &mut Session) -> Outcome {
    let file = s.write("seed.exe", &seed::binary());
    let ((_, inv), (bundle, bundle_s), (_, copy)) =
        (s.dir("inv"), s.dir("bundle"), s.dir("inv-copy"));
    let (_, view) = s.run(&[
        &file,
        "--investigate",
        &inv,
        "--question",
        "Does constant return 7?",
        "--require",
        "ssa-slice",
    ]);
    let question = view["pending"][0]["id"].as_str().unwrap_or("").to_string();
    let (_, slice) = s.run(&[
        &file,
        "--ssa-slice",
        "0x401000",
        "--return",
        "--evidence-store",
        &inv,
    ]);
    let (_, card) = s.run(&[
        &file,
        "0x401000",
        "--card",
        "--decompile",
        "--evidence-store",
        &inv,
    ]);
    let slice_id = slice["id"].as_str().unwrap_or("").to_string();
    let card_id = card["id"].as_str().unwrap_or("").to_string();
    s.run(&[
        "--investigation",
        &inv,
        "--expect-revision",
        "1",
        "--support",
        &question,
        "--cite",
        &slice_id,
    ]);
    s.run(&[
        "--investigation",
        &inv,
        "--expect-revision",
        "2",
        "--contradict",
        &question,
        "--cite",
        &card_id,
    ]);
    let (resolve_code, _) = s.run(&[
        "--investigation",
        &inv,
        "--expect-revision",
        "3",
        "--resolve",
        &question,
        "--disposition",
        "answered",
        "--note",
        "returns 7",
    ]);
    s.run(&[&file, "--export-bundle", &bundle_s, "--investigation", &inv]);
    s.run(&["--import-bundle", &bundle_s, "--investigation", &copy]);
    let (_, reopened) = s.run(&["--investigation", &copy]);
    let (_, markdown) = s.exec(&["--investigation", &copy, "--handoff"]);
    let issue = &reopened["investigation"]["issues"][0];
    let lost = reopened["evidence"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["available"] != true)
        .count() as u64;
    Outcome {
        answer: issue["state"] == "answered" && resolve_code == 0,
        evidence: issue["supporting"] == json!([slice_id])
            && issue["contradicting"] == json!([card_id])
            && issue["resolution"]["validation"] == "references_and_requirements_checked"
            && String::from_utf8_lossy(&markdown).contains("Contradicting evidence retained"),
        lost_references: lost,
        incorrect_upgrades: 0,
        artifact_bytes: directory_bytes(&bundle),
        details: json!({"history":reopened["investigation"]["history"].as_array().map(Vec::len)}),
    }
}

fn corrupt_and_stale_evidence(s: &mut Session) -> Outcome {
    let file = s.write("seed.exe", &seed::binary());
    let ((_, store), (bundle, bundle_s)) = (s.dir("store"), s.dir("bundle"));
    s.run(&[&file, "0x401000", "--card", "--evidence-store", &store]);
    let (_, manifest) = s.run(&[
        &file,
        "--export-bundle",
        &bundle_s,
        "--evidence-store",
        &store,
    ]);
    let record = bundle.join(manifest["files"][0]["path"].as_str().unwrap_or("missing"));
    std::fs::write(&record, b"{\"schema\":\"rsleigh.evidence/v1\"}").unwrap();
    let (verify_code, verify) = s.run(&["--verify-bundle", &bundle_s]);
    let (target, target_s) = s.dir("imported");
    let (import_code, _) = s.run(&["--import-bundle", &bundle_s, "--evidence-store", &target_s]);
    let (_, inv) = s.dir("inv");
    let (_, view) = s.run(&[&file, "--investigate", &inv, "--question", "q"]);
    let question = view["pending"][0]["id"].as_str().unwrap_or("").to_string();
    s.run(&[
        "--investigation",
        &inv,
        "--expect-revision",
        "1",
        "--add-question",
        "second",
    ]);
    let (stale_code, stale) = s.run(&[
        "--investigation",
        &inv,
        "--expect-revision",
        "1",
        "--add-question",
        "lost",
    ]);
    let absent = format!("sha256:{}", "0".repeat(64));
    let (missing_code, missing) = s.run(&[
        "--investigation",
        &inv,
        "--expect-revision",
        "2",
        "--resolve",
        &question,
        "--disposition",
        "answered",
        "--cite",
        &absent,
    ]);
    let (_, after) = s.run(&["--investigation", &inv]);
    let accepted = [verify_code, import_code, stale_code, missing_code]
        .iter()
        .filter(|c| **c != 1)
        .count() as u64;
    Outcome {
        answer: accepted == 0,
        evidence: verify["error_code"] == "verification_failed"
            && !target.join("records").exists()
            && stale["error_code"] == "stale_revision"
            && missing["error_code"] == "missing_evidence"
            && after["investigation"]["revision"] == 2
            && after["summary"]["answered"] == 0,
        lost_references: 0,
        incorrect_upgrades: accepted + after["summary"]["answered"].as_u64().unwrap_or(0),
        artifact_bytes: directory_bytes(&bundle),
        details: Value::Null,
    }
}

fn pair_verdict<'a>(model: &'a Value, name: &str) -> &'a Value {
    model["pairs"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|p| p["old"]["name"] == name)
        .unwrap_or(&Value::Null)
}

fn relocated_function_comparison(s: &mut Session) -> Outcome {
    let old = s.write("old.exe", &seed::binary());
    let new = s.write("relocated.exe", &variants::relocated());
    let (code, model) = s.run(&[&old, "--compare", &new, "--json"]);
    let calls = pair_verdict(&model, "calls");
    let unchanged = model["summary"]["unchanged"] == 5;
    Outcome {
        answer: code == 0 && calls["verdict"] == "unchanged" && unchanged,
        evidence: calls["dimensions"]["bytes"]["result"] == "changed"
            && calls["dimensions"]["instructions"]["result"] == "unchanged"
            && calls["explanation"]
                .as_str()
                .is_some_and(|e| e.contains("relocation"))
            && calls["new"]["address"] == "0x4010a0",
        lost_references: 0,
        incorrect_upgrades: 0,
        artifact_bytes: 0,
        details: json!({"summary":model["summary"]}),
    }
}

fn intentional_version_divergence(s: &mut Session) -> Outcome {
    let old = s.write("old.exe", &seed::binary());
    let constant = s.write("constant.exe", &variants::changed_constant());
    let callee = s.write("callee.exe", &variants::changed_callee());
    let truncated = s.write("truncated.exe", &variants::truncated());
    let renamed = s.write("renamed.exe", &variants::renamed());
    let (_, a) = s.run(&[&old, "--compare", &constant, "--json"]);
    let (_, b) = s.run(&[&old, "--compare", &callee, "--json"]);
    let (c_code, c) = s.run(&[
        &truncated,
        "--compare",
        &truncated,
        "--pair",
        "load",
        "--json",
    ]);
    let (_, d) = s.run(&[&old, "--compare", &renamed, "--json"]);
    let changed_constant = pair_verdict(&a, "constant");
    let changed_calls = pair_verdict(&b, "calls");
    // Unknown or partial inputs must not be reported as unchanged or absent.
    let upgrades = u64::from(c["pairs"][0]["verdict"] == "unchanged")
        + d["unmatched"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|u| u["status"] == "absent")
            .count() as u64;
    Outcome {
        answer: changed_constant["verdict"] == "changed"
            && a["summary"]["unchanged"] == 4
            && changed_calls["verdict"] == "changed"
            && c["pairs"][0]["verdict"] == "unknown"
            && d["summary"]["pairs"] == 4,
        evidence: changed_constant["dimensions"]["instructions"]["result"] == "changed"
            && changed_calls["dimensions"]["calls"]["result"] == "changed"
            && c_code == 2
            && d["suggestions"][0]["established"] == false,
        lost_references: 0,
        incorrect_upgrades: upgrades,
        artifact_bytes: 0,
        details: json!({"constant":a["summary"],"callee":b["summary"],"renamed":d["summary"]}),
    }
}

type TaskFn = fn(&mut Session) -> Outcome;

pub fn run(tool: &Path, report_path: &Path) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!(
        "rsleigh-workflow-eval-{}-{nonce}",
        std::process::id()
    ));
    let tasks: [(&str, &str, TaskFn); 7] = [
        (
            "capability-guided-selection",
            "Which selector answers the MIPS32 return question, given catalog support?",
            capability_guided_selection,
        ),
        (
            "portable-handoff",
            "Does exported evidence verify, move, import, and keep IDs and links?",
            portable_handoff,
        ),
        (
            "unresolved-question-retention",
            "Does an unresolved indirect call stay pending after handoff without the binary?",
            unresolved_question_retention,
        ),
        (
            "contradiction-preservation",
            "Are supporting and contradicting records retained through export/import?",
            contradiction_preservation,
        ),
        (
            "corrupt-stale-evidence",
            "Are corrupt bundles, stale revisions, and unavailable evidence rejected?",
            corrupt_and_stale_evidence,
        ),
        (
            "relocated-function-comparison",
            "Is a relocated identical function explained rather than changed?",
            relocated_function_comparison,
        ),
        (
            "intentional-version-divergence",
            "Are deliberate changes found without upgrading unknown evidence?",
            intentional_version_divergence,
        ),
    ];
    let mut results = Vec::new();
    for (id, question, task) in tasks {
        let root = base.join(id);
        std::fs::create_dir_all(&root).unwrap();
        let mut session = Session {
            tool,
            root,
            commands: vec![],
        };
        let outcome = task(&mut session);
        results.push(json!({"task":id,"question":question,
            "answer_correct":outcome.answer,"evidence_correct":outcome.evidence,
            "lost_references":outcome.lost_references,"incorrect_upgrades":outcome.incorrect_upgrades,
            "command_count":session.commands.len(),"stdout_bytes":session.total("stdout_bytes"),
            "elapsed_us":session.total("elapsed_us"),"artifact_bytes":outcome.artifact_bytes,
            "details":outcome.details,"commands":session.commands}));
    }
    let count = |key: &str| results.iter().filter(|r| r[key] == true).count();
    let sum = |key: &str| {
        results
            .iter()
            .map(|r| r[key].as_u64().unwrap_or(0))
            .sum::<u64>()
    };
    let (correct, evidence, lost, upgrades) = (
        count("answer_correct"),
        count("evidence_correct"),
        sum("lost_references"),
        sum("incorrect_upgrades"),
    );
    let report = json!({"schema":"rsleigh.agent-re-workflow-evaluation/v1",
        "tool_sha256":sha(&std::fs::read(tool).unwrap()),"host":std::env::consts::OS,
        "host_arch":std::env::consts::ARCH,"task_count":results.len(),"correct":correct,
        "evidence_correct":evidence,"lost_references":lost,"incorrect_upgrades":upgrades,
        "results":results});
    std::fs::write(report_path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    let _ = std::fs::remove_dir_all(base);
    println!(
        "{correct}/{} workflow tasks correct, {evidence} with correct evidence, {lost} lost references, {upgrades} incorrect upgrades; report: {}",
        report["task_count"],
        report_path.display()
    );
    if correct != tasks.len() || evidence != tasks.len() || lost != 0 || upgrades != 0 {
        std::process::exit(1);
    }
}
