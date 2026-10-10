//! Portable evidence records. A record wraps one unchanged agent payload with
//! its subject, producer, semantic parameters, coverage, limitations, and
//! links. Its ID hashes a versioned canonical projection that excludes
//! incidental execution detail, so warm/cold runs and moved files agree.
use super::*;
use contracts::{Kind, Operation, Role};
use std::cell::RefCell;
use std::path::PathBuf;

pub(super) const SCHEMA: &str = "rsleigh.evidence/v1";
pub(super) const CANONICALIZATION: &str = "rsleigh.evidence-canonical/v1";

/// Payload fields describing one execution rather than the observation:
/// absolute paths, timings, cache counters, and the version string already
/// carried by `producer`. Changing this list requires a new CANONICALIZATION.
const INCIDENTAL: &[&[&str]] = &[
    &["metrics"],
    &["tool_version"],
    &["file", "path"],
    &["source"],
    &["findings", "*", "binary"],
    &["old", "file", "path"],
    &["new", "file", "path"],
];

thread_local! {
    static CAPTURE: RefCell<Option<Vec<Value>>> = const { RefCell::new(None) };
}

pub(super) fn begin_capture() {
    CAPTURE.with(|c| *c.borrow_mut() = Some(Vec::new()));
}

pub(super) fn end_capture() -> Vec<Value> {
    CAPTURE.with(|c| c.borrow_mut().take().unwrap_or_default())
}

pub(super) fn capturing() -> bool {
    CAPTURE.with(|c| c.borrow().is_some())
}

/// Called by `emit`: true when the payload was captured instead of printed.
pub(super) fn capture(value: &Value) -> bool {
    CAPTURE.with(|c| match c.borrow_mut().as_mut() {
        Some(captured) => {
            captured.push(value.clone());
            true
        }
        None => false,
    })
}

/// Compact JSON with object keys sorted by UTF-8 bytes.
pub(super) fn canonical_bytes(value: &Value) -> Vec<u8> {
    fn write(value: &Value, out: &mut String) {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                out.push('{');
                for (i, key) in keys.into_iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&Value::String(key.clone()).to_string());
                    out.push(':');
                    write(&map[key], out);
                }
                out.push('}');
            }
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(item, out);
                }
                out.push(']');
            }
            other => out.push_str(&other.to_string()),
        }
    }
    let mut out = String::new();
    write(value, &mut out);
    out.into_bytes()
}

fn strip(value: &mut Value, path: &[&str]) {
    match path {
        [] => {}
        ["*", rest @ ..] => {
            if let Value::Array(items) = value {
                for item in items {
                    strip(item, rest);
                }
            }
        }
        [last] => {
            if let Value::Object(map) = value {
                map.remove(*last);
            }
        }
        [key, rest @ ..] => {
            if let Some(child) = value.get_mut(*key) {
                strip(child, rest);
            }
        }
    }
}

/// The record minus its ID and execution metadata, with incidental payload
/// fields removed. Content IDs hash exactly this value.
pub(super) fn projection(record: &Value) -> Value {
    let mut projected = record.clone();
    if let Value::Object(map) = &mut projected {
        map.remove("id");
        map.remove("execution");
    }
    if let Some(payload) = projected.get_mut("payload") {
        for path in INCIDENTAL {
            strip(payload, path);
        }
    }
    projected
}

pub(super) fn content_id(record: &Value) -> String {
    format!(
        "sha256:{}",
        compute_sha256(&canonical_bytes(&projection(record)))
    )
}

/// Validate an evidence ID and return its hexadecimal digest.
pub(super) fn parse_id(id: &str) -> Result<&str, AgentError> {
    id.strip_prefix("sha256:")
        .filter(|hex| {
            hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
        .ok_or_else(|| AgentError::new("invalid_value", format!("invalid evidence ID: {id}")))
}

/// Coverage derived from the payload. Verification recomputes it, so a
/// record cannot declare more completeness than its payload shows.
pub(super) fn coverage(kind: &str, payload: &Value) -> Value {
    let ok = payload["status"] == "ok";
    match kind {
        "card" => {
            let pages = &payload["pagination"];
            let pseudocode = &payload["pseudocode"];
            let truncated = pages["instructions"]["truncated"] == true
                || pages["operations"]["truncated"] == true
                || pseudocode["truncated"] == true;
            json!({
                "instructions":pages["instructions"], "operations":pages["operations"],
                "pseudocode":if pseudocode.is_null() { Value::Null } else {
                    json!({"bytes_total":pseudocode["bytes_total"],"truncated":pseudocode["truncated"]})
                },
                "complete":ok && !truncated && !pages.is_null(),
            })
        }
        "ssa-slice" => {
            let slice = &payload["slice"];
            let mut boundaries = std::collections::BTreeMap::<String, u64>::new();
            for node in slice["nodes"].as_array().into_iter().flatten() {
                if let Some(reason) = node["boundary"].as_str() {
                    *boundaries.entry(reason.to_string()).or_default() += 1;
                }
            }
            json!({
                "nodes":slice["nodes"].as_array().map(Vec::len),
                "boundaries":boundaries, "stops":slice["stops"], "truncated":slice["truncated"],
                "complete":ok && slice["complete"] == true,
            })
        }
        "agent-brief" => {
            let limits = &payload["limits"];
            json!({
                "functions_returned":limits["functions_returned"], "functions_total":limits["functions_total"],
                "findings_returned":limits["findings_returned"], "findings_total":limits["findings_total"],
                "complete":ok && limits["functions_returned"] == limits["functions_total"]
                    && limits["findings_returned"] == limits["findings_total"],
            })
        }
        "compare" => json!({
            "summary":payload["summary"], "limits":payload["limits"],
            "complete":ok && payload["limits"]["pairs_truncated"] == false,
        }),
        _ => json!({"complete":ok}),
    }
}

/// Warnings and diagnostic codes surfaced from the payload.
pub(super) fn limitations(payload: &Value) -> Value {
    let mut codes = std::collections::BTreeSet::new();
    for diagnostic in payload["diagnostics"].as_array().into_iter().flatten() {
        if let Some(code) = diagnostic["code"].as_str() {
            codes.insert(code.to_string());
        }
    }
    json!({
        "warnings":payload["warnings"].as_array().cloned().unwrap_or_default(),
        "diagnostic_codes":codes,
        "selection_error":payload["selection_error"]["code"],
        "error":payload["error"],
    })
}

/// Binary identity bound into every record: content hash plus the container
/// facts needed to interpret addresses.
pub(super) fn subject(data: &[u8]) -> Value {
    let sha256 = compute_sha256(data);
    let parsed = parse_object_lenient(data)
        .ok()
        .and_then(|obj| parse_binary(&obj, data).map(|(arch, segs, _)| (obj, arch, segs)));
    match parsed {
        Some((obj, arch, segs)) => {
            let (format, imagebase) = agent_format_and_base(&obj, &segs);
            json!({"binary_sha256":sha256,"format":format,"architecture":format!("{arch:?}"),
                "imagebase":format!("0x{imagebase:x}"),"mode":"native"})
        }
        None => json!({"binary_sha256":sha256,"format":"unknown","architecture":null,
            "imagebase":null,"mode":"native"}),
    }
}

/// Analysis inputs beyond the binary, identified by content, never by path.
fn profile(binary_path: &Path) -> Value {
    let mut dsym = binary_path.as_os_str().to_os_string();
    dsym.push(".dSYM");
    let dsym = Path::new(&dsym)
        .join("Contents/Resources/DWARF")
        .join(binary_path.file_name().unwrap_or_default());
    let companions: Vec<Value> = [("pdb", binary_path.with_extension("pdb")), ("dsym", dsym)]
        .into_iter()
        .map(|(kind, path)| match std::fs::read(&path) {
            Ok(bytes) => json!({"kind":kind,"sha256":compute_sha256(&bytes)}),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                json!({"kind":kind,"present":false})
            }
            Err(_) => json!({"kind":kind,"unreadable":true}),
        })
        .collect();
    json!({"opaque_fold":std::env::var("RSLEIGH_OPAQUE_FOLD").as_deref() == Ok("1"),
        "debug_companions":companions})
}

/// Semantic parameters only, normalized: counts as numbers, addresses in
/// lowercase hex, and function targets as the resolved address.
fn parameters(op: &Operation, args: &[String], start: usize, payload: &Value) -> Value {
    let resolved = payload["function"]["address"]
        .as_str()
        .or_else(|| payload["function_address"].as_str())
        .map(str::to_string);
    let normalize = |kind: Kind, raw: &str| -> Value {
        match kind {
            Kind::Count => raw.parse::<u64>().map(Value::from).unwrap_or(json!(raw)),
            Kind::Address => raw
                .strip_prefix("0x")
                .or_else(|| raw.strip_prefix("0X"))
                .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                .map(|a| json!(format!("0x{a:x}")))
                .unwrap_or(json!(raw)),
            Kind::Function => json!(resolved.clone().unwrap_or_else(|| raw.to_string())),
            Kind::Binary => match std::fs::read(raw) {
                Ok(bytes) => json!({"sha256":compute_sha256(&bytes)}),
                Err(_) => json!({"unreadable":true}),
            },
            _ => json!(raw),
        }
    };
    let mut parameters = serde_json::Map::new();
    let mut i = start;
    while i < args.len() {
        let arg = args[i].as_str();
        if let Some(flag) = op.flag(arg) {
            let value = if flag.takes_value() {
                i += 1;
                normalize(flag.kind, args.get(i).map(String::as_str).unwrap_or(""))
            } else {
                Value::Bool(true)
            };
            let selects_mode = flag.name == op.mode.name && !flag.takes_value();
            if flag.role == Role::Semantic && !selects_mode {
                let key = arg.trim_start_matches("--").to_string();
                if flag.repeatable {
                    let entry = parameters.entry(key).or_insert_with(|| json!([]));
                    if let Value::Array(values) = entry {
                        values.push(value);
                    }
                } else {
                    parameters.insert(key, value);
                }
            }
        } else if let Some(positional) = op.positional {
            parameters.insert(positional.to_lowercase(), normalize(Kind::Function, arg));
        }
        i += 1;
    }
    Value::Object(parameters)
}

/// Assemble a record. `execution` holds what the ID deliberately ignores.
pub(super) fn build(
    op: &Operation,
    args: &[String],
    binary_path: &str,
    data: &[u8],
    payload: Value,
    references: Vec<String>,
    exit_code: u8,
) -> Value {
    let mut record = json!({
        "schema":SCHEMA, "canonicalization":CANONICALIZATION, "kind":op.id,
        "subject":subject(data),
        "producer":{"tool":"rsleigh","version":env!("CARGO_PKG_VERSION"),
            "build":capabilities::tool_json()["build"],"profile":profile(Path::new(binary_path))},
        "operation":{"id":op.id,"schema":op.schema,"parameters":parameters(op, args, 2, &payload)},
        "status":payload["status"],
        "coverage":coverage(op.id, &payload),
        "limitations":limitations(&payload),
        "interpretation":{"trust":agent_trust_json(),
            "finding_confidence":"pattern | heuristic | proved, scoped to each finding's producer and model"},
        "references":references,
        "payload":payload,
    });
    record["id"] = json!(content_id(&record));
    let recorded_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    record["execution"] = json!({"argv":&args[1..],"exit_code":exit_code,
        "recorded_at_unix_ms":recorded_at});
    record
}

/// Structural and identity checks for one record. A valid record is
/// internally consistent; it is not a verified claim about the binary.
pub(super) fn validate_record(record: &Value) -> Result<(), String> {
    if record["schema"] != SCHEMA {
        return Err(format!("expected {SCHEMA}"));
    }
    if record["canonicalization"] != CANONICALIZATION {
        return Err(format!(
            "unsupported canonicalization {}",
            record["canonicalization"]
        ));
    }
    let id = record["id"].as_str().ok_or("record has no ID")?;
    parse_id(id).map_err(String::from)?;
    if content_id(record) != id {
        return Err(format!("{id}: content ID does not match record contents"));
    }
    let payload = &record["payload"];
    let kind = record["kind"].as_str().ok_or("record has no kind")?;
    if record["operation"]["schema"] != payload["schema"] {
        return Err(format!("{id}: payload schema differs from operation"));
    }
    if record["status"] != payload["status"]
        || !matches!(record["status"].as_str(), Some("ok" | "partial" | "failed"))
    {
        return Err(format!("{id}: status differs from payload"));
    }
    if record["coverage"] != coverage(kind, payload) {
        return Err(format!("{id}: declared coverage differs from payload"));
    }
    if record["limitations"] != limitations(payload) {
        return Err(format!("{id}: declared limitations differ from payload"));
    }
    let sha = record["subject"]["binary_sha256"].as_str().unwrap_or("");
    if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{id}: invalid subject hash"));
    }
    let references = record["references"]
        .as_array()
        .ok_or_else(|| format!("{id}: references must be an array"))?;
    let mut previous: Option<&str> = None;
    for reference in references {
        let reference = reference
            .as_str()
            .ok_or_else(|| format!("{id}: invalid reference"))?;
        parse_id(reference).map_err(String::from)?;
        if reference == id || previous.is_some_and(|p| p >= reference) {
            return Err(format!(
                "{id}: references must be sorted, unique, and not self"
            ));
        }
        previous = Some(reference);
    }
    Ok(())
}

pub(super) fn record_path(store: &Path, id: &str) -> Result<PathBuf, AgentError> {
    Ok(store
        .join("records")
        .join(format!("{}.json", parse_id(id)?)))
}

/// Load and validate one stored record.
pub(super) fn load(store: &Path, id: &str) -> Result<Value, AgentError> {
    let path = record_path(store, id)?;
    let bytes = std::fs::read(&path).map_err(|e| {
        AgentError::new(
            "missing_evidence",
            format!("evidence {id} is unavailable: {e}"),
        )
    })?;
    let record: Value = serde_json::from_slice(&bytes)
        .map_err(|e| AgentError::new("verification_failed", format!("{id}: {e}")))?;
    validate_record(&record).map_err(|e| AgentError::new("verification_failed", e))?;
    if record["id"] != id {
        return Err(AgentError::new(
            "verification_failed",
            format!("{id}: stored under another record's ID"),
        ));
    }
    Ok(record)
}

/// Every valid record in a store, sorted by ID. Invalid files fail loudly.
pub(super) fn list(store: &Path) -> Result<Vec<Value>, AgentError> {
    let directory = store.join("records");
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(AgentError::new("input_unreadable", e.to_string())),
    };
    let mut records = Vec::new();
    for entry in entries {
        let name = entry
            .map_err(|e| AgentError::new("input_unreadable", e.to_string()))?
            .file_name();
        let Some(hex) = name.to_str().and_then(|n| n.strip_suffix(".json")) else {
            continue;
        };
        records.push(load(store, &format!("sha256:{hex}"))?);
    }
    records.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Ok(records)
}

/// Persist a record. Content addressing makes repeated stores idempotent:
/// the first stored execution of an observation is kept.
pub(super) fn store(store: &Path, record: &Value) -> Result<&'static str, AgentError> {
    let id = record["id"].as_str().unwrap_or_default();
    let path = record_path(store, id)?;
    let write_error = |e: std::io::Error| AgentError::new("write_failed", e.to_string());
    if path.exists() {
        load(store, id)?;
        return Ok("existing");
    }
    std::fs::create_dir_all(path.parent().unwrap()).map_err(write_error)?;
    let pending = path.with_extension(format!(
        "{}-{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let bytes = serde_json::to_vec_pretty(record).map_err(|e| e.to_string())?;
    std::fs::write(&pending, bytes).map_err(write_error)?;
    std::fs::rename(&pending, &path).map_err(|e| {
        let _ = std::fs::remove_file(&pending);
        write_error(e)
    })?;
    Ok("created")
}

fn references(args: &[String]) -> Result<Vec<String>, AgentError> {
    let mut references = values_arg(args, "--derived-from")?
        .into_iter()
        .map(|id| parse_id(id).map(|_| id.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    references.sort();
    references.dedup();
    Ok(references)
}

/// Fail before analysis when requested links cannot be satisfied.
pub(super) fn preflight(args: &[String], data: &[u8]) -> Result<(), AgentError> {
    let references = references(args)?;
    if references.is_empty() {
        return Ok(());
    }
    let store = value_arg(args, "--evidence-store")?.ok_or_else(|| {
        AgentError::new(
            "invalid_combination",
            "--derived-from requires --evidence-store",
        )
    })?;
    let sha = compute_sha256(data);
    for id in references {
        if load(Path::new(store), &id)?["subject"]["binary_sha256"] != sha {
            return Err(AgentError::new(
                "invalid_combination",
                format!("{id} describes a different binary"),
            ));
        }
    }
    Ok(())
}

/// Wrap the single captured payload, persist it when requested, and emit it.
pub(super) fn finish(
    op: &Operation,
    args: &[String],
    data: &[u8],
    captured: Vec<Value>,
    exit_code: u8,
) -> Result<(), AgentError> {
    let [payload]: [Value; 1] = captured.try_into().map_err(|c: Vec<Value>| {
        AgentError::new(
            "command_failed",
            format!("expected one payload for evidence, captured {}", c.len()),
        )
    })?;
    let record = build(
        op,
        args,
        &args[1],
        data,
        payload,
        references(args)?,
        exit_code,
    );
    if let Some(directory) = value_arg(args, "--evidence-store")? {
        store(Path::new(directory), &record)?;
    }
    emit(&record);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_form_is_order_independent_and_compact() {
        let a: Value = serde_json::from_str(r#"{"b":[1,{"z":true,"a":null}],"a":"é"}"#).unwrap();
        let b = json!({"a":"é","b":[1,{"a":null,"z":true}]});
        assert_eq!(canonical_bytes(&a), canonical_bytes(&b));
        assert_eq!(
            String::from_utf8(canonical_bytes(&b)).unwrap(),
            r#"{"a":"é","b":[1,{"a":null,"z":true}]}"#
        );
    }

    #[test]
    fn incidental_fields_do_not_change_ids_but_evidence_does() {
        let record = |path: &str, metrics: u64, constant: u64| {
            let mut record = json!({"schema":SCHEMA,"canonicalization":CANONICALIZATION,"kind":"x",
                "payload":{"status":"ok","file":{"path":path,"sha256":"00"},"metrics":{"elapsed":metrics},
                    "findings":[{"binary":path,"value":constant}]},
                "execution":{"argv":[path]}});
            record["id"] = json!(content_id(&record));
            record
        };
        let base = record("/a/sample", 1, 7);
        assert_eq!(base["id"], record("/elsewhere/sample", 99, 7)["id"]);
        assert_ne!(base["id"], record("/a/sample", 1, 8)["id"]);
    }
}
