//! Investigation ledger. One directory holds the question, target identity,
//! evidence store (`records/`), and immutable revisions (`revisions/`). The
//! highest complete revision is authoritative; `investigation.json` mirrors it.
//! Recorded dispositions are distinguishable from evidence-checked answers.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

pub(super) const SCHEMA: &str = "rsleigh.investigation/v1";
const VIEW_SCHEMA: &str = "rsleigh.investigation-view/v1";
const STATES: [&str; 4] = ["open", "answered", "withdrawn", "out_of_scope"];
const ACTIONS: [&str; 7] = [
    "--add-question",
    "--add-unknowns",
    "--observe",
    "--infer",
    "--support",
    "--contradict",
    "--resolve",
];
const OPERATIONS: [&str; 4] = ["agent-brief", "card", "ssa-slice", "compare"];

/// Slice boundaries that a larger traversal allowance might resolve:
/// (reason, flag, key in slice.limits, catalog cap).
const LIMITS: [(&str, &str, &str, u64); 5] = [
    ("node_limit", "--max-nodes", "max_nodes", 256),
    ("depth_limit", "--max-depth", "max_depth", 32),
    ("call_depth_limit", "--max-call-depth", "max_call_depth", 8),
    ("function_limit", "--max-functions", "max_functions", 32),
    (
        "traversal_work_limit",
        "--max-traversal-work",
        "max_work",
        1_000_000,
    ),
];
/// Values supplied from outside the analyzed function.
const EXTERNAL_VALUES: [&str; 4] = [
    "unknown_value",
    "external_input",
    "external_or_unknown_value",
    "missing_call_argument",
];
const CALLS: [&str; 5] = [
    "unknown_call",
    "unmodeled_call",
    "external_call",
    "function_unavailable",
    "unsupported_calling_convention",
];

fn revision_dir(root: &Path) -> PathBuf {
    root.join("revisions")
}

pub(super) fn revision_name(revision: u64) -> String {
    format!("{revision:06}.json")
}

fn short_hash(value: &Value) -> String {
    compute_sha256(&evidence::canonical_bytes(value))[..12].to_string()
}

fn ids(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

/// Every evidence ID the document cites, in any section.
pub(super) fn referenced(doc: &Value) -> BTreeSet<String> {
    let mut cited = BTreeSet::new();
    for issue in doc["issues"].as_array().into_iter().flatten() {
        cited.extend(issue["source"].as_str().map(str::to_string));
        cited.extend(ids(&issue["supporting"]));
        cited.extend(ids(&issue["contradicting"]));
        cited.extend(ids(&issue["resolution"]["evidence"]));
    }
    for section in ["observations", "inferences"] {
        for entry in doc[section].as_array().into_iter().flatten() {
            cited.extend(ids(&entry["evidence"]));
        }
    }
    cited
}

/// Structural invariants of one revision.
pub(super) fn validate_document(doc: &Value) -> Result<(), String> {
    if doc["schema"] != SCHEMA {
        return Err(format!("expected {SCHEMA}"));
    }
    let revision = doc["revision"]
        .as_u64()
        .filter(|r| *r > 0)
        .ok_or("invalid revision")?;
    if doc["history"].as_array().map(Vec::len) != Some(revision as usize) {
        return Err("history does not match revision".into());
    }
    if !doc["question"].is_string()
        || doc["target"]["binary_sha256"].as_str().map(str::len) != Some(64)
    {
        return Err("missing question or target identity".into());
    }
    let mut seen = BTreeSet::new();
    for issue in doc["issues"].as_array().ok_or("issues must be an array")? {
        let id = issue["id"].as_str().ok_or("issue without ID")?;
        if !seen.insert(id.to_string()) {
            return Err(format!("duplicate issue {id}"));
        }
        let state = issue["state"].as_str().unwrap_or("");
        if !STATES.contains(&state) {
            return Err(format!("{id}: invalid state {state}"));
        }
        if (state == "open") != issue["resolution"].is_null() {
            return Err(format!("{id}: resolution must accompany a closed state"));
        }
        if state == "answered" && ids(&issue["resolution"]["evidence"]).is_empty() {
            return Err(format!("{id}: an answer must cite evidence"));
        }
        // Boundary locations feed rendered commands; accept only the exact
        // forms this tool emits, so imported documents cannot smuggle text.
        if issue["origin"] == "slice_boundary" {
            let location = &issue["location"];
            let reason = issue["key"]["reason"].as_str().unwrap_or("");
            if !["function_address", "root_function"]
                .iter()
                .all(|k| location[*k].as_str().is_some_and(is_address))
                || reason.is_empty()
                || !reason.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
            {
                return Err(format!("{id}: invalid boundary location or reason"));
            }
        }
    }
    if doc["file_hint"]
        .as_str()
        .is_some_and(|hint| hint.contains('\0'))
    {
        return Err("invalid file hint".into());
    }
    for section in ["observations", "inferences"] {
        for entry in doc[section].as_array().ok_or("sections must be arrays")? {
            let id = entry["id"].as_str().ok_or("entry without ID")?;
            if !seen.insert(id.to_string()) {
                return Err(format!("duplicate entry {id}"));
            }
        }
    }
    for id in referenced(doc) {
        evidence::parse_id(&id).map_err(String::from)?;
    }
    Ok(())
}

/// Every committed revision, oldest first; numbering must be contiguous.
pub(super) fn revisions(root: &Path) -> Result<Vec<Value>, AgentError> {
    let directory = revision_dir(root);
    let entries = std::fs::read_dir(&directory).map_err(|e| {
        AgentError::new(
            "input_unreadable",
            format!("no investigation at {}: {e}", root.display()),
        )
    })?;
    let mut numbers = Vec::new();
    for entry in entries {
        let name = entry
            .map_err(|e| AgentError::new("input_unreadable", e.to_string()))?
            .file_name();
        let name = name.to_string_lossy();
        if let Some(n) = name
            .strip_suffix(".json")
            .and_then(|n| n.parse::<u64>().ok())
        {
            numbers.push(n);
        }
    }
    numbers.sort_unstable();
    if numbers.is_empty() || numbers.iter().enumerate().any(|(i, n)| *n != i as u64 + 1) {
        return Err(AgentError::new(
            "verification_failed",
            "investigation revisions are missing or not contiguous",
        ));
    }
    numbers
        .into_iter()
        .map(|n| {
            let path = directory.join(revision_name(n));
            let doc: Value = std::fs::read(&path)
                .map_err(|e| e.to_string())
                .and_then(|b| serde_json::from_slice(&b).map_err(|e| e.to_string()))
                .and_then(|doc: Value| validate_document(&doc).map(|_| doc))
                .map_err(|e| {
                    AgentError::new("verification_failed", format!("revision {n}: {e}"))
                })?;
            if doc["revision"] != n {
                return Err(AgentError::new(
                    "verification_failed",
                    format!("revision file {n} holds revision {}", doc["revision"]),
                ));
            }
            Ok(doc)
        })
        .collect()
}

pub(super) fn load(root: &Path) -> Result<Value, AgentError> {
    Ok(revisions(root)?.pop().expect("at least one revision"))
}

/// Atomically claim the next revision number, then refresh the mirror.
/// Linking a complete temporary file fails if another writer claimed it.
pub(super) fn commit(root: &Path, doc: &Value) -> Result<(), AgentError> {
    let write_error = |e: std::io::Error| AgentError::new("write_failed", e.to_string());
    let directory = revision_dir(root);
    std::fs::create_dir_all(&directory).map_err(write_error)?;
    let nonce = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let bytes = serde_json::to_vec_pretty(doc).map_err(|e| e.to_string())?;
    let pending = directory.join(format!(".pending-{nonce}.tmp"));
    std::fs::write(&pending, &bytes).map_err(write_error)?;
    let revision = doc["revision"].as_u64().unwrap_or(0);
    let claimed = std::fs::hard_link(&pending, directory.join(revision_name(revision)));
    let _ = std::fs::remove_file(&pending);
    match claimed {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(AgentError::new(
                "stale_revision",
                format!("revision {revision} was already committed; reload and retry"),
            ))
        }
        Err(e) => return Err(write_error(e)),
    }
    let mirror = root.join(format!(".investigation-{nonce}.tmp"));
    std::fs::write(&mirror, &bytes).map_err(write_error)?;
    std::fs::rename(&mirror, root.join("investigation.json")).map_err(write_error)
}

fn record_function(record: &Value) -> Option<&str> {
    record["payload"]["function"]["address"]
        .as_str()
        .or_else(|| record["payload"]["function_address"].as_str())
}

fn satisfies(requirement: &Value, record: &Value) -> bool {
    let operations = ids(&requirement["operations"]);
    record["status"] != "failed"
        && (operations.is_empty() || operations.iter().any(|op| record["kind"] == op.as_str()))
        && (requirement["function_address"].is_null()
            || record_function(record) == requirement["function_address"].as_str())
}

/// Load cited evidence from the investigation store; it must describe the
/// investigation's target. Unavailable evidence is an error, never skipped.
fn cite(root: &Path, doc: &Value, cited: &[&str]) -> Result<Vec<Value>, AgentError> {
    cited
        .iter()
        .map(|id| {
            let record = evidence::load(root, id)?;
            if record["subject"]["binary_sha256"] != doc["target"]["binary_sha256"] {
                return Err(AgentError::new(
                    "invalid_combination",
                    format!("{id} describes a different binary"),
                ));
            }
            Ok(record)
        })
        .collect()
}

fn requirements(args: &[String]) -> Result<Vec<Value>, AgentError> {
    let operations: Vec<&str> = values_arg(args, "--require")?;
    for op in &operations {
        if !OPERATIONS.contains(op) {
            return Err(AgentError::new(
                "invalid_value",
                format!("--require accepts {}", OPERATIONS.join(", ")),
            ));
        }
    }
    Ok(vec![
        json!({"operations":operations,"function_address":null}),
    ])
}

fn question_issue(text: &str, requirements: Vec<Value>, revision: u64, origin: &str) -> Value {
    json!({
        "id":format!("q-{}", short_hash(&json!({"origin":"analyst","text":text}))),
        "origin":origin, "text":text, "state":"open",
        "supporting":[], "contradicting":[], "requirements":requirements,
        "resolution":null, "created_revision":revision, "updated_revision":revision,
    })
}

/// Convert unresolved slice boundaries into deduplicated issues. The key is
/// target/profile, selector, context call chain, node origin, and reason.
fn boundary_issues(
    record: &Value,
    nodes: &[usize],
    revision: u64,
) -> Result<Vec<Value>, AgentError> {
    if record["kind"] != "ssa-slice" {
        return Err(AgentError::new(
            "invalid_value",
            "--add-unknowns requires an ssa-slice evidence record",
        ));
    }
    let slice = &record["payload"]["slice"];
    let all = slice["nodes"].as_array().cloned().unwrap_or_default();
    let selected: Vec<usize> = if nodes.is_empty() {
        (0..all.len())
            .filter(|i| all[*i]["boundary"].is_string())
            .collect()
    } else {
        nodes.to_vec()
    };
    let contexts = slice["contexts"].as_array().cloned().unwrap_or_default();
    let chain = |mut context: Option<u64>| {
        let mut origins = Vec::new();
        while let Some(id) = context {
            let Some(entry) = contexts.iter().find(|c| c["id"] == id) else {
                break;
            };
            if !entry["call_origin"].is_null() {
                origins.push(entry["call_origin"].clone());
            }
            context = entry["caller_context"].as_u64();
        }
        origins
    };
    let root_function = record["payload"]["function_address"].clone();
    // Root selection only: reruns with other traversal limits that reach the
    // same boundary are the same unknown.
    let parameters = &record["operation"]["parameters"];
    let selector: serde_json::Map<String, Value> = [
        "ssa-slice",
        "var",
        "call-site",
        "arg",
        "return",
        "at",
        "condition",
    ]
    .iter()
    .filter_map(|key| parameters.get(*key).map(|v| (key.to_string(), v.clone())))
    .collect();
    let mut issues = Vec::new();
    for index in selected {
        let node = all.get(index).ok_or_else(|| {
            AgentError::new("invalid_value", format!("slice has no node {index}"))
        })?;
        let Some(reason) = node["boundary"].as_str() else {
            return Err(AgentError::new(
                "invalid_value",
                format!("node {index} has no unresolved boundary"),
            ));
        };
        let function = format!("0x{:x}", node["function_address"].as_u64().unwrap_or(0));
        let key = json!({
            "target":record["subject"]["binary_sha256"],
            "profile":{"build":record["producer"]["build"],"profile":record["producer"]["profile"]},
            "selector":selector,
            "context":chain(node["context_id"].as_u64()),
            "function_address":function,
            "origin":{"operations":node["origins"]["operations"],"var_id":node["var_id"]},
            "reason":reason,
        });
        let limit = LIMITS.iter().any(|(r, ..)| *r == reason);
        let requirement = if limit {
            json!({"operations":["ssa-slice"],"function_address":root_function})
        } else {
            json!({"operations":["card","ssa-slice"],"function_address":function})
        };
        let origin = node["origins"]["operations"][0]["instruction_address"]
            .as_u64()
            .map(|a| format!(" (origin 0x{a:x})"))
            .unwrap_or_default();
        issues.push(json!({
            "id":format!("u-{}", short_hash(&key)), "origin":"slice_boundary",
            "text":format!("Unresolved {reason} in {function}, SSA variable {}{origin}", node["var_id"]),
            "state":"open", "source":record["id"], "key":key,
            "location":{"function_address":function,"root_function":root_function,"var_id":node["var_id"],
                "node_index":index,"call":node["call"],"limits":slice["limits"],"parameters":parameters},
            "supporting":[], "contradicting":[], "requirements":[requirement],
            "resolution":null, "created_revision":revision, "updated_revision":revision,
        }));
    }
    Ok(issues)
}

fn merge_ids(target: &mut Value, added: &[&str]) {
    let mut all: BTreeSet<String> = ids(target).into_iter().collect();
    all.extend(added.iter().map(|s| s.to_string()));
    *target = json!(all);
}

fn summary(doc: &Value) -> Value {
    let count = |state: &str| {
        doc["issues"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|i| i["state"] == state)
            .count()
    };
    json!({"open":count("open"),"answered":count("answered"),"withdrawn":count("withdrawn"),
        "out_of_scope":count("out_of_scope"),
        "verified_answers":count("answered"),
        "contradicted":doc["issues"].as_array().into_iter().flatten()
            .filter(|i| !ids(&i["contradicting"]).is_empty()).count(),
        "observations":doc["observations"].as_array().map(Vec::len),
        "inferences":doc["inferences"].as_array().map(Vec::len)})
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Shell {
    Posix,
    PowerShell,
}

/// Render argv for a shell. Flags, decimal numbers, and 0x addresses stay
/// bare; every other argument (paths, names, text) is quoted.
/// Canonical `0x` lowercase-hex address, as emitted by slices and cards.
fn is_address(value: &str) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|h| !h.is_empty() && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// Flags a rendered command may leave unquoted: catalog flags plus the legacy
/// modes that brief suggestions and platform notes name.
fn known_flag(arg: &str) -> bool {
    matches!(arg, "--xrefs" | "--ssa-json")
        || contracts::OPERATIONS
            .iter()
            .any(|op| op.flag(arg).is_some())
}

/// Render argv for a shell. Only known flags, decimal numbers, and 0x hex
/// addresses stay bare. Everything else, including any value that came from
/// an investigation document (possibly imported from another machine), is
/// quoted, so a crafted path or address cannot inject shell syntax.
pub(super) fn render_command(argv: &[String], shell: Shell) -> String {
    let bare = |a: &str| {
        known_flag(a)
            || (!a.is_empty() && a.bytes().all(|b| b.is_ascii_digit()))
            || a.strip_prefix("0x")
                .is_some_and(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()))
    };
    let mut command = String::from("rsleigh");
    for arg in argv {
        command.push(' ');
        if bare(arg) {
            command.push_str(arg);
        } else {
            match shell {
                Shell::Posix => command.push_str(&shell_quote(arg)),
                Shell::PowerShell => command.push_str(&format!("'{}'", arg.replace('\'', "''"))),
            }
        }
    }
    command
}

fn parameter_argv(parameters: &Value) -> Vec<String> {
    let mut argv = Vec::new();
    for (key, value) in parameters.as_object().into_iter().flatten() {
        if key == "ssa-slice" {
            continue;
        }
        match value {
            Value::Bool(true) => argv.push(format!("--{key}")),
            Value::Array(values) => {
                for v in values {
                    argv.push(format!("--{key}"));
                    argv.push(
                        v.as_str()
                            .map(str::to_string)
                            .unwrap_or_else(|| v.to_string()),
                    );
                }
            }
            other => {
                argv.push(format!("--{key}"));
                argv.push(
                    other
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| other.to_string()),
                );
            }
        }
    }
    argv
}

/// Smallest catalog commands that could supply each open issue's missing
/// evidence. Every suggestion is validated against its operation contract.
fn next_queries(
    doc: &Value,
    store: &str,
    file: &str,
    shell: Shell,
    records: &BTreeMap<String, Value>,
) -> Vec<Value> {
    let architecture = doc["target"]["architecture"].as_str().unwrap_or("");
    let helpers = ["X86_64", "X86_32", "AArch64", "ARM32"].contains(&architecture);
    let card = |function: &str| -> Vec<String> {
        [
            "FILE",
            function,
            "--card",
            "--json",
            "--pcode",
            "--evidence-store",
            store,
        ]
        .map(str::to_string)
        .to_vec()
    };
    let mut queries: Vec<Value> = Vec::new();
    let mut push = |issue: &Value,
                    operation: &str,
                    argv: Vec<String>,
                    reason: String,
                    note: Option<String>| {
        let mut validated = vec!["rsleigh".to_string()];
        validated.extend(argv.iter().cloned());
        let valid = contracts::OPERATIONS
            .iter()
            .find(|op| op.id == operation)
            .is_some_and(|op| contracts::validate(op, &validated, 2).is_ok());
        // Documents can be imported; an invalid suggestion is dropped, not trusted.
        if !valid || queries.iter().any(|q| q["argv"] == json!(argv)) {
            return;
        }
        let rendered: Vec<String> = argv
            .iter()
            .map(|a| {
                if a == "FILE" {
                    file.to_string()
                } else {
                    a.clone()
                }
            })
            .collect();
        queries.push(
            json!({"issue":issue["id"],"operation":operation,"argv":argv,
            "command":render_command(&rendered, shell),"reason":reason,"platform_note":note}),
        );
    };
    for issue in doc["issues"].as_array().into_iter().flatten() {
        if issue["state"] != "open" {
            continue;
        }
        if issue["origin"] == "slice_boundary" {
            let reason = issue["key"]["reason"].as_str().unwrap_or("");
            let function = issue["location"]["function_address"].as_str().unwrap_or("");
            let root = issue["location"]["root_function"]
                .as_str()
                .unwrap_or(function);
            if let Some((_, flag, key, cap)) = LIMITS.iter().find(|(r, ..)| *r == reason) {
                let current = issue["location"]["limits"][key].as_u64().unwrap_or(0);
                if current < *cap {
                    let raised = current.saturating_mul(2).clamp(1, *cap);
                    let mut argv: Vec<String> =
                        ["FILE", "--ssa-slice", root].map(str::to_string).to_vec();
                    let mut parameters = issue["location"]["parameters"].clone();
                    if let Some(map) = parameters.as_object_mut() {
                        map.insert(flag.trim_start_matches("--").to_string(), json!(raised));
                    }
                    argv.extend(parameter_argv(&parameters));
                    argv.extend(["--evidence-store".to_string(), store.to_string()]);
                    push(
                        issue,
                        "ssa-slice",
                        argv,
                        format!("raise {flag} from {current} to {raised}"),
                        None,
                    );
                } else {
                    push(
                        issue,
                        "card",
                        card(function),
                        format!("{flag} is at its cap; inspect the P-code directly"),
                        None,
                    );
                }
            } else if CALLS.contains(&reason) && !helpers {
                push(issue, "card", card(function), "inspect the call instruction and its P-code".into(),
                    Some(format!("helper-call traversal is unsupported for {architecture}; a slice cannot follow this call")));
            } else if EXTERNAL_VALUES.contains(&reason) {
                push(
                    issue,
                    "card",
                    card(function),
                    "the value enters from outside this function".into(),
                    Some(format!(
                        "find callers with: {}",
                        render_command(
                            &[file.to_string(), "--xrefs".into(), function.to_string()],
                            shell
                        )
                    )),
                );
            } else {
                push(
                    issue,
                    "card",
                    card(function),
                    format!("inspect the P-code behind {reason}"),
                    None,
                );
            }
            continue;
        }
        let cited: Vec<&Value> = ids(&issue["supporting"])
            .iter()
            .filter_map(|id| records.get(id))
            .collect();
        for requirement in issue["requirements"].as_array().into_iter().flatten() {
            if cited.iter().any(|record| satisfies(requirement, record)) {
                continue;
            }
            let operations = ids(&requirement["operations"]);
            match requirement["function_address"].as_str() {
                Some(function) => push(
                    issue,
                    "card",
                    card(function),
                    "requirement needs evidence for this function".into(),
                    None,
                ),
                None if operations.is_empty() || operations.iter().any(|o| o == "agent-brief") => {
                    push(
                        issue,
                        "agent-brief",
                        [
                            "FILE",
                            "--agent-brief",
                            "--limit",
                            "5",
                            "--evidence-store",
                            store,
                        ]
                        .map(str::to_string)
                        .to_vec(),
                        "map candidate functions, then cite card or slice evidence".into(),
                        None,
                    )
                }
                None => push(
                    issue,
                    "agent-brief",
                    [
                        "FILE",
                        "--agent-brief",
                        "--limit",
                        "5",
                        "--evidence-store",
                        store,
                    ]
                    .map(str::to_string)
                    .to_vec(),
                    format!(
                        "choose a function, then record {} evidence",
                        operations.join(" or ")
                    ),
                    None,
                ),
            }
        }
    }
    queries
}

fn store_records(root: &Path, doc: &Value) -> BTreeMap<String, Value> {
    referenced(doc)
        .into_iter()
        .filter_map(|id| evidence::load(root, &id).ok().map(|r| (id, r)))
        .collect()
}

fn view(
    root: &Path,
    doc: &Value,
    args: &[String],
    file: Option<&str>,
) -> Result<Value, AgentError> {
    let shell = match value_arg(args, "--shell")? {
        None if cfg!(windows) => Shell::PowerShell,
        None | Some("posix") => Shell::Posix,
        Some("powershell") => Shell::PowerShell,
        Some(other) => {
            return Err(AgentError::new(
                "invalid_value",
                format!("--shell accepts posix or powershell, not {other}"),
            ))
        }
    };
    let records = store_records(root, doc);
    let evidence: Vec<Value> = referenced(doc)
        .into_iter()
        .map(|id| match records.get(&id) {
            Some(r) => json!({"id":id,"available":true,"kind":r["kind"],"status":r["status"],
                "complete":r["coverage"]["complete"],"function_address":record_function(r)}),
            None => json!({"id":id,"available":false}),
        })
        .collect();
    let file = file
        .map(str::to_string)
        .or_else(|| doc["file_hint"].as_str().map(str::to_string))
        .unwrap_or_else(|| "FILE".into());
    // A leading '-' would be parsed as an option even when quoted.
    let file = if file.starts_with('-') {
        format!("./{file}")
    } else {
        file
    };
    let store = root.to_string_lossy().into_owned();
    Ok(json!({
        "schema":VIEW_SCHEMA, "status":"ok", "investigation":doc, "summary":summary(doc),
        "pending":doc["issues"].as_array().into_iter().flatten()
            .filter(|i| i["state"] == "open").map(|i| json!({"id":i["id"],"text":i["text"]})).collect::<Vec<_>>(),
        "evidence":evidence,
        "next_queries":next_queries(doc, &store, &file, shell, &records),
    }))
}

fn none_if_empty(out: &mut String, start: usize) {
    if out.len() == start {
        out.push_str("- none\n");
    }
}

fn handoff(view: &Value) -> String {
    let doc = &view["investigation"];
    let s = |v: &Value| {
        v.as_str()
            .map(str::to_string)
            .unwrap_or_else(|| v.to_string())
    };
    let list = |v: &Value| {
        let items = ids(v);
        if items.is_empty() {
            "none".to_string()
        } else {
            items.join(", ")
        }
    };
    let mut out = format!(
        "# Investigation {} (revision {})\n\nQuestion: {}\nBinary: sha256={} format={} arch={} image_base={}\nTool: rsleigh {}\n",
        s(&doc["id"]), doc["revision"], s(&doc["question"]),
        s(&doc["target"]["binary_sha256"]), s(&doc["target"]["format"]),
        s(&doc["target"]["architecture"]), s(&doc["target"]["imagebase"]),
        s(&doc["created_by"]["version"]),
    );
    let summary = &view["summary"];
    out.push_str(&format!(
        "\n## Status\n\nOpen: {} · Answered (evidence-checked): {} · Withdrawn (not answers): {} · Out of scope: {} · Contradicted: {}\n",
        summary["open"], summary["answered"], summary["withdrawn"], summary["out_of_scope"], summary["contradicted"]
    ));
    let issues: Vec<&Value> = doc["issues"].as_array().into_iter().flatten().collect();
    out.push_str("\n## Unresolved\n\n");
    let start = out.len();
    for issue in issues.iter().filter(|i| i["state"] == "open") {
        out.push_str(&format!(
            "- [{}] {}\n  - Supporting: {}; contradicting: {}\n",
            s(&issue["id"]),
            s(&issue["text"]),
            list(&issue["supporting"]),
            list(&issue["contradicting"])
        ));
        if let Some(source) = issue["source"].as_str() {
            out.push_str(&format!("  - Source: {source}\n"));
        }
        for query in view["next_queries"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|q| q["issue"] == issue["id"])
        {
            out.push_str(&format!(
                "  - Next: `{}` — {}\n",
                s(&query["command"]),
                s(&query["reason"])
            ));
            if let Some(note) = query["platform_note"].as_str() {
                out.push_str(&format!("  - Note: {note}\n"));
            }
        }
    }
    none_if_empty(&mut out, start);
    out.push_str("\n## Closed\n\n");
    let start = out.len();
    for issue in issues.iter().filter(|i| i["state"] != "open") {
        let resolution = &issue["resolution"];
        out.push_str(&format!(
            "- [{}] {} — {}: {} (evidence: {}; {})\n",
            s(&issue["id"]),
            s(&issue["text"]),
            s(&issue["state"]),
            resolution["note"].as_str().unwrap_or(""),
            list(&resolution["evidence"]),
            s(&resolution["validation"])
        ));
        if !ids(&issue["contradicting"]).is_empty() {
            out.push_str(&format!(
                "  - Contradicting evidence retained: {}\n",
                list(&issue["contradicting"])
            ));
        }
    }
    none_if_empty(&mut out, start);
    out.push_str("\n## Observations\n\n");
    let start = out.len();
    for entry in doc["observations"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "- [{}] {} (evidence: {})\n",
            s(&entry["id"]),
            s(&entry["text"]),
            list(&entry["evidence"])
        ));
    }
    none_if_empty(&mut out, start);
    out.push_str("\n## Analyst inferences (provisional, not verified)\n\n");
    let start = out.len();
    for entry in doc["inferences"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "- [{}] {} (evidence: {})\n",
            s(&entry["id"]),
            s(&entry["text"]),
            list(&entry["evidence"])
        ));
    }
    none_if_empty(&mut out, start);
    out.push_str("\n## Evidence\n\n");
    let start = out.len();
    for record in view["evidence"].as_array().into_iter().flatten() {
        if record["available"] == true {
            out.push_str(&format!(
                "- {} {} {} function={} complete={}\n",
                s(&record["id"]),
                s(&record["kind"]),
                s(&record["status"]),
                s(&record["function_address"]),
                record["complete"]
            ));
        } else {
            out.push_str(&format!("- {} (unavailable)\n", s(&record["id"])));
        }
    }
    none_if_empty(&mut out, start);
    out.push_str("\n## History\n\n");
    for entry in doc["history"].as_array().into_iter().flatten() {
        out.push_str(&format!(
            "- r{} {} {}\n",
            entry["revision"],
            s(&entry["action"]),
            entry["subject"].as_str().unwrap_or("")
        ));
    }
    out
}

fn emit_view(
    root: &Path,
    doc: &Value,
    args: &[String],
    file: Option<&str>,
    change: Value,
) -> Result<(), AgentError> {
    let mut view = view(root, doc, args, file)?;
    if args.iter().any(|a| a == "--handoff") {
        print!("{}", handoff(&view));
        return Ok(());
    }
    if !change.is_null() {
        view["change"] = change;
    }
    emit(&view);
    Ok(())
}

pub(super) fn create(binary_path: &str, data: &[u8], args: &[String]) -> Result<u8, AgentError> {
    let root = Path::new(value_arg(args, "--investigate")?.expect("validated mode value"));
    if revision_dir(root).exists() {
        return Err(AgentError::new(
            "stale_revision",
            format!("an investigation already exists at {}", root.display()),
        ));
    }
    let question = value_arg(args, "--question")?.ok_or_else(|| {
        AgentError::new(
            "invalid_combination",
            "--investigate requires --question TEXT",
        )
    })?;
    let target = evidence::subject(data);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let id = format!(
        "inv-{}",
        short_hash(&json!({"target":target,"question":question,"nonce":nonce.to_string()}))
    );
    let doc = json!({
        "schema":SCHEMA, "id":id, "revision":1, "question":question, "target":target,
        "file_hint":binary_path, "created_by":capabilities::tool_json(),
        "issues":[question_issue(question, requirements(args)?, 1, "question")],
        "observations":[], "inferences":[],
        "history":[{"revision":1,"action":"create","subject":id}],
    });
    validate_document(&doc).map_err(|e| AgentError::new("command_failed", e))?;
    commit(root, &doc)?;
    emit_view(root, &doc, args, Some(binary_path), Value::Null)?;
    Ok(0)
}

fn issue_index(doc: &Value, id: &str) -> Result<usize, AgentError> {
    doc["issues"]
        .as_array()
        .and_then(|issues| issues.iter().position(|i| i["id"] == id))
        .ok_or_else(|| AgentError::new("target_not_found", format!("no issue {id}")))
}

/// Show (no action) or apply exactly one revision-checked update.
pub(super) fn run(source: Option<(&str, &[u8])>, args: &[String]) -> Result<u8, AgentError> {
    let root = Path::new(value_arg(args, "--investigation")?.expect("validated mode value"));
    let mut doc = load(root)?;
    if let Some((_, data)) = source {
        if doc["target"]["binary_sha256"] != compute_sha256(data) {
            return Err(AgentError::new(
                "verification_failed",
                "investigation target SHA-256 does not match the supplied binary",
            ));
        }
    }
    let file = source.map(|(path, _)| path);
    let actions: Vec<&str> = ACTIONS
        .iter()
        .copied()
        .filter(|a| args.iter().any(|arg| arg == a))
        .collect();
    let update_only = [
        "--expect-revision",
        "--cite",
        "--node",
        "--disposition",
        "--note",
        "--require",
    ];
    if actions.is_empty() {
        if let Some(flag) = update_only.iter().find(|f| args.iter().any(|a| a == *f)) {
            return Err(AgentError::new(
                "invalid_combination",
                format!("{flag} needs an update action"),
            ));
        }
        emit_view(root, &doc, args, file, Value::Null)?;
        return Ok(0);
    }
    if actions.len() > 1 || args.iter().any(|a| a == "--handoff") {
        return Err(AgentError::new(
            "invalid_combination",
            "apply exactly one update action per revision, without --handoff",
        ));
    }
    let expected = value_arg(args, "--expect-revision")?.ok_or_else(|| {
        AgentError::new("invalid_combination", "updates require --expect-revision N")
    })?;
    let current = doc["revision"].as_u64().unwrap_or(0);
    if expected.parse::<u64>().ok() != Some(current) {
        return Err(AgentError::new(
            "stale_revision",
            format!(
                "investigation is at revision {current}, not {expected}; reload before updating"
            ),
        ));
    }
    let revision = current + 1;
    let cited = values_arg(args, "--cite")?;
    let records = cite(root, &doc, &cited)?;
    let action = actions[0];
    let value = value_arg(args, action)?.expect("validated action value");
    let mut change = json!({"action":action.trim_start_matches("--"),"revision":revision});
    let mut subject = value.to_string();
    match action {
        "--add-question" => {
            let issue = question_issue(value, requirements(args)?, revision, "analyst");
            subject = issue["id"].as_str().unwrap_or_default().to_string();
            if doc["issues"]
                .as_array()
                .unwrap()
                .iter()
                .any(|i| i["id"] == issue["id"])
            {
                return Err(AgentError::new(
                    "invalid_value",
                    format!("question {subject} already exists"),
                ));
            }
            doc["issues"].as_array_mut().unwrap().push(issue);
        }
        "--add-unknowns" => {
            let record = cite(root, &doc, &[value])?.remove(0);
            let nodes = values_arg(args, "--node")?
                .into_iter()
                .map(|n| {
                    n.parse::<usize>().map_err(|_| {
                        AgentError::new("invalid_value", "--node requires a node index")
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let (mut added, mut existing) = (vec![], vec![]);
            for issue in boundary_issues(&record, &nodes, revision)? {
                let issues = doc["issues"].as_array_mut().unwrap();
                if issues.iter().any(|i| i["id"] == issue["id"]) {
                    existing.push(issue["id"].clone());
                } else {
                    added.push(issue["id"].clone());
                    issues.push(issue);
                }
            }
            if added.is_empty() {
                return Err(AgentError::new(
                    "invalid_value",
                    format!(
                        "no new unresolved boundaries in {value} ({} already tracked)",
                        existing.len()
                    ),
                ));
            }
            change["added"] = json!(added);
            change["existing"] = json!(existing);
        }
        "--observe" | "--infer" => {
            if action == "--observe" && records.is_empty() {
                return Err(AgentError::new(
                    "invalid_combination",
                    "--observe requires at least one --cite ID",
                ));
            }
            let section = if action == "--observe" {
                "observations"
            } else {
                "inferences"
            };
            let prefix = if action == "--observe" { "obs" } else { "inf" };
            let id = format!("{prefix}-{}", doc[section].as_array().unwrap().len() + 1);
            subject = id.clone();
            let mut entry = json!({"id":id,"text":value,"evidence":cited,"revision":revision});
            if action == "--infer" {
                entry["assessment"] = json!("provisional");
                entry["kind"] = json!("analyst_inference");
            }
            doc[section].as_array_mut().unwrap().push(entry);
        }
        "--support" | "--contradict" => {
            if records.is_empty() {
                return Err(AgentError::new(
                    "invalid_combination",
                    format!("{action} requires at least one --cite ID"),
                ));
            }
            let index = issue_index(&doc, value)?;
            let field = if action == "--support" {
                "supporting"
            } else {
                "contradicting"
            };
            let issue = &mut doc["issues"][index];
            merge_ids(&mut issue[field], &cited);
            issue["updated_revision"] = json!(revision);
        }
        "--resolve" => {
            let index = issue_index(&doc, value)?;
            if doc["issues"][index]["state"] != "open" {
                return Err(AgentError::new(
                    "invalid_combination",
                    format!("{value} is already closed"),
                ));
            }
            let disposition = value_arg(args, "--disposition")?.ok_or_else(|| {
                AgentError::new(
                    "invalid_combination",
                    "--resolve requires --disposition answered|withdrawn|out-of-scope",
                )
            })?;
            let state = match disposition {
                "answered" => "answered",
                "withdrawn" => "withdrawn",
                "out-of-scope" => "out_of_scope",
                other => {
                    return Err(AgentError::new(
                        "invalid_value",
                        format!("unknown disposition {other}"),
                    ))
                }
            };
            let issue = &doc["issues"][index];
            let mut evidence: BTreeSet<String> = cited.iter().map(|s| s.to_string()).collect();
            let validation = if state == "answered" {
                // Supporting evidence counts toward an answer only if still available.
                evidence.extend(ids(&issue["supporting"]));
                let available = cite(
                    root,
                    &doc,
                    &evidence.iter().map(String::as_str).collect::<Vec<_>>(),
                )?;
                if available.is_empty() {
                    return Err(AgentError::new(
                        "requirements_unmet",
                        "an answer must cite available evidence",
                    ));
                }
                for requirement in issue["requirements"].as_array().into_iter().flatten() {
                    if !available
                        .iter()
                        .any(|record| satisfies(requirement, record))
                    {
                        return Err(AgentError::new(
                            "requirements_unmet",
                            format!(
                                "{value}: no cited evidence satisfies requirement {requirement}"
                            ),
                        ));
                    }
                }
                "references_and_requirements_checked"
            } else {
                "analyst_disposition_only"
            };
            let issue = &mut doc["issues"][index];
            issue["state"] = json!(state);
            issue["updated_revision"] = json!(revision);
            issue["resolution"] = json!({"disposition":state,"note":value_arg(args, "--note")?,
                "evidence":evidence,"revision":revision,"validation":validation});
        }
        _ => unreachable!("cataloged action"),
    }
    doc["revision"] = json!(revision);
    doc["history"]
        .as_array_mut()
        .unwrap()
        .push(json!({"revision":revision,
        "action":action.trim_start_matches("--"),"subject":subject}));
    validate_document(&doc).map_err(|e| AgentError::new("command_failed", e))?;
    commit(root, &doc)?;
    emit_view(root, &doc, args, file, change)?;
    Ok(0)
}

/// Bundle attachment: the current document plus every revision.
pub(super) fn attachment(
    root: &Path,
    sha256: &str,
) -> Result<(Value, bundle::Attachment), AgentError> {
    let history = revisions(root)?;
    let doc = history.last().expect("at least one revision").clone();
    if doc["target"]["binary_sha256"] != sha256 {
        return Err(AgentError::new(
            "invalid_combination",
            "the investigation describes a different binary",
        ));
    }
    let mut artifacts = vec![(
        "investigation.json".to_string(),
        serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())?,
    )];
    let mut names = Vec::new();
    for revision in &history {
        let name = format!(
            "revision-{}",
            revision_name(revision["revision"].as_u64().unwrap_or(0))
        );
        artifacts.push((
            name.clone(),
            serde_json::to_vec_pretty(revision).map_err(|e| e.to_string())?,
        ));
        names.push(name);
    }
    let value = json!({"id":doc["id"],"revision":doc["revision"],"file":"investigation.json","revisions":names});
    Ok((
        doc,
        bundle::Attachment {
            manifest_key: "investigation",
            manifest_value: value,
            artifacts,
        },
    ))
}

/// Validate a bundle's attachments: none, or exactly one investigation whose
/// revisions are contiguous and whose cited evidence is inside the bundle.
pub(super) fn validate_bundle(bundle: &bundle::Bundle) -> Result<(), String> {
    let declared = &bundle.manifest["investigation"];
    if declared.is_null() {
        return match bundle.attachments.keys().next() {
            Some(name) => Err(format!("undeclared bundle artifact: {name}")),
            None => Ok(()),
        };
    }
    let names = ids(&declared["revisions"]);
    let mut expected: BTreeSet<String> = names.iter().cloned().collect();
    expected.insert("investigation.json".into());
    let present: BTreeSet<String> = bundle.attachments.keys().cloned().collect();
    if expected != present {
        return Err("investigation artifacts differ from the manifest".into());
    }
    let parse = |name: &str| -> Result<Value, String> {
        let doc: Value = serde_json::from_slice(&bundle.attachments[name])
            .map_err(|e| format!("{name}: {e}"))?;
        validate_document(&doc).map_err(|e| format!("{name}: {e}"))?;
        Ok(doc)
    };
    let mut last = Value::Null;
    for (i, name) in names.iter().enumerate() {
        let doc = parse(name)?;
        if doc["revision"] != (i + 1) as u64
            || *name != format!("revision-{}", revision_name(i as u64 + 1))
        {
            return Err("investigation revisions are not contiguous".into());
        }
        last = doc;
    }
    let current = parse("investigation.json")?;
    if current != last
        || declared["revision"] != current["revision"]
        || declared["id"] != current["id"]
    {
        return Err("investigation.json is not the latest revision".into());
    }
    if current["target"]["binary_sha256"] != bundle.manifest["subject"]["binary_sha256"] {
        return Err("investigation describes a different binary".into());
    }
    for id in referenced(&current) {
        if !bundle.records.contains_key(&id) {
            return Err(format!("investigation cites {id}, which the bundle lacks"));
        }
    }
    Ok(())
}

/// Import a bundled investigation into an empty investigation directory.
pub(super) fn import(bundle: &bundle::Bundle, args: &[String]) -> Result<Value, AgentError> {
    let declared = &bundle.manifest["investigation"];
    if declared.is_null() {
        return Ok(Value::Null);
    }
    let Some(root) = value_arg(args, "--investigation")? else {
        return Ok(json!({"id":declared["id"],"imported":false,
            "reason":"pass --investigation DIR to import the investigation document"}));
    };
    let root = Path::new(root);
    if revision_dir(root).exists() {
        return Err(AgentError::new(
            "stale_revision",
            format!("an investigation already exists at {}", root.display()),
        ));
    }
    for name in ids(&declared["revisions"]) {
        let doc: Value =
            serde_json::from_slice(&bundle.attachments[&name]).map_err(|e| e.to_string())?;
        commit(root, &doc)?;
    }
    Ok(json!({"id":declared["id"],"imported":true,"revision":declared["revision"]}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(architecture: &str, reason: &str, limits: Value) -> Value {
        json!({"target":{"architecture":architecture},"issues":[{
            "id":"u-1","origin":"slice_boundary","state":"open",
            "key":{"reason":reason},
            "location":{"function_address":"0x401060","root_function":"0x401000","limits":limits,
                "parameters":{"ssa-slice":"0x401000","return":true,"max-nodes":200}},
            "requirements":[],"supporting":[]}]})
    }

    fn next(architecture: &str, reason: &str, limits: Value) -> Vec<Value> {
        next_queries(
            &doc(architecture, reason, limits),
            "inv",
            "a b.exe",
            Shell::Posix,
            &BTreeMap::new(),
        )
    }

    #[test]
    fn next_queries_reflect_missing_evidence_and_platform() {
        let raised = next("X86_32", "call_depth_limit", json!({"max_call_depth":2}));
        assert_eq!(raised[0]["operation"], "ssa-slice");
        let argv = ids(&raised[0]["argv"]);
        assert!(
            argv.windows(2).any(|w| w == ["--max-call-depth", "4"]),
            "{argv:?}"
        );
        // Other original limits are kept, not reset to defaults.
        assert!(
            argv.windows(2).any(|w| w == ["--max-nodes", "200"]),
            "{argv:?}"
        );
        assert_eq!(
            raised[0]["command"],
            "rsleigh 'a b.exe' --ssa-slice 0x401000 --max-call-depth 4 --max-nodes 200 --return --evidence-store 'inv'"
        );
        let capped = next("X86_32", "call_depth_limit", json!({"max_call_depth":8}));
        assert_eq!(capped[0]["operation"], "card");
        let mips = next("MIPS32", "unknown_call", json!({}));
        assert!(mips[0]["platform_note"]
            .as_str()
            .unwrap()
            .contains("unsupported for MIPS32"));
        assert!(next("X86_32", "unknown_call", json!({}))[0]["platform_note"].is_null());
        let external = next("AArch64", "unknown_value", json!({}));
        assert!(external[0]["platform_note"]
            .as_str()
            .unwrap()
            .contains("--xrefs 0x401060"));
    }

    #[test]
    fn untrusted_document_values_are_quoted_or_rejected() {
        let hostile = "--x; touch /tmp/pwned";
        let rendered = render_command(
            &[hostile.to_string(), "--card".into(), "$(id)".into()],
            Shell::Posix,
        );
        assert_eq!(rendered, "rsleigh '--x; touch /tmp/pwned' --card '$(id)'");
        let mut document = doc("X86_32", "unknown_call", json!({}));
        document["schema"] = json!(SCHEMA);
        document["revision"] = json!(1);
        document["history"] = json!([{}]);
        document["question"] = json!("q");
        document["target"]["binary_sha256"] = json!("0".repeat(64));
        document["observations"] = json!([]);
        document["inferences"] = json!([]);
        document["issues"][0]["resolution"] = Value::Null;
        document["issues"][0]["location"]["root_function"] = json!("0x401000");
        validate_document(&document).unwrap();
        document["issues"][0]["location"]["function_address"] = json!("0x401060; rm -rf ~");
        assert!(validate_document(&document).is_err());
        document["issues"][0]["location"]["function_address"] = json!("0x401060");
        document["issues"][0]["key"]["reason"] = json!("x`id`");
        assert!(validate_document(&document).is_err());
    }

    #[test]
    fn commands_quote_paths_and_text_per_shell() {
        let argv: Vec<String> = ["it's.exe", "--card", "0x401000", "12", "--note", "a b"]
            .map(str::to_string)
            .to_vec();
        assert_eq!(
            render_command(&argv, Shell::Posix),
            r#"rsleigh 'it'\''s.exe' --card 0x401000 12 --note 'a b'"#
        );
        assert_eq!(
            render_command(&argv, Shell::PowerShell),
            "rsleigh 'it''s.exe' --card 0x401000 12 --note 'a b'"
        );
    }
}
