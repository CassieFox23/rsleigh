//! Evidence bundles: selected records plus their referenced dependencies,
//! published as an immutable generation through the index machinery.
//! Verification is offline; importing copies records and never executes a
//! saved command or turns imported analysis into a trusted runtime cache.
use super::*;
use std::collections::BTreeMap;

pub(super) const SCHEMA: &str = "rsleigh.evidence-bundle/v1";
const VERIFICATION_SCHEMA: &str = "rsleigh.bundle-verification/v1";
const IMPORT_SCHEMA: &str = "rsleigh.bundle-import/v1";

fn record_file(id: &str) -> Result<String, AgentError> {
    Ok(format!("record-{}.json", evidence::parse_id(id)?))
}

fn summary(records: &BTreeMap<String, Value>) -> Value {
    let count = |status: &str| records.values().filter(|r| r["status"] == status).count();
    json!({"records":records.len(),"ok":count("ok"),"partial":count("partial"),"failed":count("failed"),
        "complete":records.values().filter(|r| r["coverage"]["complete"] == true).count()})
}

fn entry(record: &Value) -> Result<Value, AgentError> {
    let id = record["id"].as_str().unwrap_or_default();
    Ok(
        json!({"id":id,"kind":record["kind"],"status":record["status"],
        "file":record_file(id)?,"references":record["references"]}),
    )
}

/// Records plus the transitive closure of their references, all describing
/// `sha256`. A missing dependency or another binary's record fails export.
pub(super) fn closure(
    store: &Path,
    roots: Vec<String>,
    sha256: &str,
) -> Result<BTreeMap<String, Value>, AgentError> {
    let mut records = BTreeMap::new();
    let mut pending = roots;
    while let Some(id) = pending.pop() {
        if records.contains_key(&id) {
            continue;
        }
        let record = evidence::load(store, &id)?;
        if record["subject"]["binary_sha256"] != sha256 {
            return Err(AgentError::new(
                "invalid_combination",
                format!("{id} describes a different binary; bundles hold one target"),
            ));
        }
        for reference in record["references"].as_array().into_iter().flatten() {
            pending.push(reference.as_str().unwrap_or_default().to_string());
        }
        records.insert(id, record);
    }
    Ok(records)
}

/// Shared subject of a single-target record set.
fn common_subject(records: &BTreeMap<String, Value>) -> Result<Value, String> {
    let mut subjects = records.values().map(|r| &r["subject"]);
    let first = subjects.next().ok_or("bundle declares no records")?.clone();
    if subjects.any(|s| *s != first) {
        return Err("records describe different targets".into());
    }
    Ok(first)
}

/// Extra artifacts contributed by other modules (investigations).
pub(super) struct Attachment {
    pub manifest_key: &'static str,
    pub manifest_value: Value,
    pub artifacts: Vec<(String, Vec<u8>)>,
}

pub(super) fn publish(
    out: &Path,
    records: &BTreeMap<String, Value>,
    attachment: Option<Attachment>,
) -> Result<Value, AgentError> {
    let subject = common_subject(records).map_err(|e| AgentError::new("missing_evidence", e))?;
    let mut artifacts = Vec::new();
    let mut entries = Vec::new();
    for (id, record) in records {
        artifacts.push((
            record_file(id)?,
            serde_json::to_vec_pretty(record).map_err(|e| e.to_string())?,
        ));
        entries.push(entry(record)?);
    }
    let mut manifest = json!({
        "schema":SCHEMA, "status":"ok", "canonicalization":evidence::CANONICALIZATION,
        "subject":subject, "exported_by":capabilities::tool_json(),
        "records":entries, "coverage":summary(records),
        "scope":"checksums establish consistency, not the truth or authorship of claims",
    });
    if let Some(attachment) = attachment {
        manifest[attachment.manifest_key] = attachment.manifest_value;
        artifacts.extend(attachment.artifacts);
    }
    let artifacts: Vec<(&str, Vec<u8>)> = artifacts
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.clone()))
        .collect();
    index::publish(out, manifest, &artifacts)
        .map_err(|e| AgentError::new("write_failed", format!("cannot publish bundle: {e}")))
}

pub(super) fn export(data: &[u8], args: &[String]) -> Result<u8, AgentError> {
    let out = value_arg(args, "--export-bundle")?.expect("validated mode value");
    let investigation = value_arg(args, "--investigation")?;
    let store = value_arg(args, "--evidence-store")?
        .or(investigation)
        .ok_or_else(|| {
            AgentError::new(
                "invalid_combination",
                "--export-bundle requires --evidence-store or --investigation",
            )
        })?;
    let sha256 = compute_sha256(data);
    let mut roots: Vec<String> = values_arg(args, "--record")?
        .into_iter()
        .map(str::to_string)
        .collect();
    for id in &roots {
        evidence::parse_id(id)?;
    }
    let selected = !roots.is_empty();
    let mut attachment = None;
    if let Some(directory) = investigation {
        let (doc, attached) = investigation::attachment(Path::new(directory), &sha256)?;
        roots.extend(investigation::referenced(&doc));
        attachment = Some(attached);
    }
    if !selected {
        roots = evidence::list(Path::new(store))?
            .into_iter()
            .filter(|r| r["subject"]["binary_sha256"] == sha256)
            .filter_map(|r| r["id"].as_str().map(str::to_string))
            .collect();
    }
    if roots.is_empty() {
        return Err(AgentError::new(
            "missing_evidence",
            "the store holds no evidence for this binary",
        ));
    }
    roots.sort();
    roots.dedup();
    let records = closure(Path::new(store), roots, &sha256)?;
    emit(&publish(Path::new(out), &records, attachment)?);
    Ok(0)
}

pub(super) struct Bundle {
    pub manifest: Value,
    pub records: BTreeMap<String, Value>,
    /// Non-record artifacts, keyed by name, for attachment validators.
    pub attachments: BTreeMap<String, Vec<u8>>,
}

/// Offline integrity check: generation, checksums, record IDs, declared
/// coverage, single target, and closed references.
pub(super) fn read(root: &Path) -> Result<Bundle, String> {
    let (bytes, manifest) = index::read_manifest(root)?;
    if manifest["schema"] != SCHEMA {
        return Err(format!("expected {SCHEMA}"));
    }
    if manifest["canonicalization"] != evidence::CANONICALIZATION {
        return Err("unsupported canonicalization".into());
    }
    let mut artifacts: BTreeMap<String, Vec<u8>> = index::read_artifacts(root, &bytes, &manifest)?
        .into_iter()
        .collect();
    let entries = manifest["records"]
        .as_array()
        .ok_or("bundle has no record list")?;
    let mut records = BTreeMap::new();
    for declared in entries {
        let id = declared["id"].as_str().ok_or("record entry has no ID")?;
        let file = record_file(id).map_err(String::from)?;
        if declared["file"] != file {
            return Err(format!("{id}: unexpected record file"));
        }
        let bytes = artifacts
            .remove(&file)
            .ok_or_else(|| format!("{id}: record file missing from generation"))?;
        let record: Value =
            serde_json::from_slice(&bytes).map_err(|e| format!("{id}: invalid record: {e}"))?;
        evidence::validate_record(&record)?;
        if record["id"] != id {
            return Err(format!("{id}: file holds another record"));
        }
        if *declared != entry(&record).map_err(String::from)? {
            return Err(format!("{id}: manifest entry differs from record"));
        }
        if records.insert(id.to_string(), record).is_some() {
            return Err(format!("{id}: declared twice"));
        }
    }
    let subject = common_subject(&records)?;
    if manifest["subject"] != subject {
        return Err("manifest subject differs from records".into());
    }
    for (id, record) in &records {
        for reference in record["references"].as_array().into_iter().flatten() {
            let reference = reference.as_str().unwrap_or_default();
            if !records.contains_key(reference) {
                return Err(format!(
                    "{id}: references {reference}, which the bundle lacks"
                ));
            }
        }
    }
    if manifest["coverage"] != summary(&records) {
        return Err("declared coverage differs from records".into());
    }
    Ok(Bundle {
        manifest,
        records,
        attachments: artifacts,
    })
}

/// Bind a verified bundle to an optional source binary.
fn source_binding(bundle: &Bundle, source: Option<&[u8]>) -> Result<&'static str, AgentError> {
    match source {
        None => Ok("not_checked"),
        Some(data) if bundle.manifest["subject"]["binary_sha256"] == compute_sha256(data) => {
            Ok("verified")
        }
        Some(_) => Err(AgentError::new(
            "verification_failed",
            "bundle subject SHA-256 does not match the supplied binary",
        )),
    }
}

fn read_verified(
    dir: &str,
    extra: impl Fn(&Bundle) -> Result<(), String>,
) -> Result<Bundle, AgentError> {
    let bundle = read(Path::new(dir)).map_err(|e| AgentError::new("verification_failed", e))?;
    extra(&bundle).map_err(|e| AgentError::new("verification_failed", e))?;
    Ok(bundle)
}

/// Distinct tool builds that produced the records; a bundle may mix builds.
fn producers(records: &BTreeMap<String, Value>) -> Vec<Value> {
    let mut seen = std::collections::BTreeMap::new();
    for record in records.values() {
        let producer = &record["producer"];
        let identity = json!({"version":producer["version"],"build":producer["build"]});
        seen.entry(evidence::canonical_bytes(&identity))
            .or_insert(identity);
    }
    seen.into_values().collect()
}

fn checks(bundle: &Bundle, binding: &str) -> Value {
    let attachments = !bundle.attachments.is_empty();
    json!({"integrity":"verified","record_ids":"verified","references":"verified",
        "coverage":"verified","source_binding":binding,
        "attachments":if attachments { "verified" } else { "none" }})
}

pub(super) fn verify(
    source: Option<&[u8]>,
    args: &[String],
    extra: impl Fn(&Bundle) -> Result<(), String>,
) -> Result<u8, AgentError> {
    let dir = value_arg(args, "--verify-bundle")?.expect("validated mode value");
    let bundle = read_verified(dir, extra)?;
    let binding = source_binding(&bundle, source)?;
    // Verification completeness, not evidence completeness: partial records
    // stay partial and are counted under `records`.
    let status = if binding == "verified" {
        "ok"
    } else {
        "partial"
    };
    emit(&json!({
        "schema":VERIFICATION_SCHEMA, "status":status, "valid":true,
        "checks":checks(&bundle, binding),
        "verified_scope":if binding == "verified" {
            "bundle integrity and source binary identity"
        } else {
            "bundle integrity only; supply FILE to check source binding"
        },
        "subject":bundle.manifest["subject"], "generation":bundle.manifest["generation"],
        "records":summary(&bundle.records),
        "producers":producers(&bundle.records),
    }));
    Ok(status_exit(status))
}

pub(super) fn import(
    source: Option<&[u8]>,
    args: &[String],
    extra: impl Fn(&Bundle) -> Result<(), String>,
    attach: impl FnOnce(&Bundle) -> Result<Value, AgentError>,
) -> Result<u8, AgentError> {
    if let Some(directory) = value_arg(args, "--investigation")? {
        // Refuse before copying anything: imports never merge investigations.
        if Path::new(directory).join("revisions").exists() {
            return Err(AgentError::new(
                "stale_revision",
                format!("an investigation already exists at {directory}"),
            ));
        }
    }
    let dir = value_arg(args, "--import-bundle")?.expect("validated mode value");
    let store = value_arg(args, "--evidence-store")?
        .or(value_arg(args, "--investigation")?)
        .ok_or_else(|| {
            AgentError::new(
                "invalid_combination",
                "--import-bundle requires --evidence-store or --investigation",
            )
        })?;
    let bundle = read_verified(dir, extra)?;
    let binding = source_binding(&bundle, source)?;
    let (mut created, mut existing) = (0, 0);
    for record in bundle.records.values() {
        match evidence::store(Path::new(store), record)? {
            "created" => created += 1,
            _ => existing += 1,
        }
    }
    let attached = attach(&bundle)?;
    emit(&json!({
        "schema":IMPORT_SCHEMA, "status":"ok", "store":store,
        "checks":checks(&bundle, binding), "subject":bundle.manifest["subject"],
        "records":{"imported":created,"existing":existing,"total":bundle.records.len()},
        "investigation":attached,
        "scope":"records were copied as observations; no saved command was executed",
    }));
    Ok(0)
}
