//! `--xrefs` and `--search` under the agent contract. Text stays the default;
//! `--json` emits `rsleigh.xrefs/v1` or `rsleigh.search/v1`. Both scan a
//! bounded window of each function, so a scan that stops inside a longer
//! function makes the result partial rather than silently incomplete.
use super::*;

/// Raw images keep the legacy renderers; agent contracts need a container.
pub(super) const RAW_LEGACY: [&str; 2] = ["xrefs", "search"];

fn lookup_error((code, message): LookupError) -> AgentError {
    AgentError::new(code, message)
}

fn scan_diagnostics(truncated_scans: usize) -> Vec<Value> {
    if truncated_scans == 0 {
        return Vec::new();
    }
    vec![diagnostic(
        "scan",
        "scan_window",
        &format!(
            "{truncated_scans} function(s) longer than {XREF_SCAN_BYTES} bytes were scanned only in part"
        ),
    )]
}

fn json_output(args: &[String]) -> bool {
    args.iter().any(|a| a == "--json")
}

pub(super) fn xrefs(binary_path: &str, data: &[u8], args: &[String]) -> Result<u8, AgentError> {
    let target = value_arg(args, "--xrefs")?.expect("validated mode value");
    let xrefs = collect_xrefs(binary_path, data, target).map_err(lookup_error)?;
    let mut diagnostics = scan_diagnostics(xrefs.truncated_scans);
    if xrefs.pseudocode.is_empty() {
        diagnostics.push(diagnostic(
            "decompile",
            "empty_output",
            "the target produced no pseudocode; callees and strings are unavailable",
        ));
    }
    let status = evidence_status(true, &diagnostics);
    if !json_output(args) {
        print_xrefs(&xrefs);
        return Ok(status_exit(status));
    }
    let mut callers: std::collections::BTreeMap<(u64, &str), usize> =
        std::collections::BTreeMap::new();
    for (address, name) in &xrefs.call_sites {
        *callers.entry((*address, name.as_str())).or_default() += 1;
    }
    emit(&json!({
        "schema":"rsleigh.xrefs/v1", "status":status, "tool_version":env!("CARGO_PKG_VERSION"),
        "file":{"sha256":compute_sha256(data)},
        "function":{"name":xrefs.name, "address":format!("0x{:x}", xrefs.address)},
        "callers":callers.iter().map(|((address, name), sites)| json!({
            "address":format!("0x{address:x}"), "name":name, "call_sites":sites,
        })).collect::<Vec<_>>(),
        "call_sites":xrefs.call_sites.len(),
        "callees":xrefs.callees, "strings":xrefs.strings,
        "derivation":{
            "callers":"direct call instructions to the function or its import stub",
            "callees":"call expressions in the function's pseudocode (hypothesis)",
            "strings":"string literals in the function's pseudocode",
        },
        "diagnostics":diagnostics,
        "limits":{"scan_bytes_per_function":XREF_SCAN_BYTES, "truncated_scans":xrefs.truncated_scans},
    }));
    Ok(status_exit(status))
}

pub(super) fn search(binary_path: &str, data: &[u8], args: &[String]) -> Result<u8, AgentError> {
    let op = contracts::find("--search").expect("search contract");
    let queries = contracts::validate(op, args, 2)?;
    let [query] = queries[..] else {
        return Err(AgentError::new(
            "invalid_target",
            "--search requires exactly one QUERY",
        ));
    };
    let has = |flag: &str| args.iter().any(|a| a == flag);
    let kinds: Vec<&str> = ["--api", "--const", "--tag"]
        .into_iter()
        .filter(|flag| has(flag))
        .collect();
    let kind = match kinds[..] {
        [] => "text",
        [flag] => flag.trim_start_matches("--"),
        _ => {
            return Err(AgentError::new(
                "invalid_combination",
                "select at most one of --api, --const, --tag",
            ))
        }
    };
    let results = collect_search(
        binary_path,
        data,
        query,
        kind == "api",
        kind == "const",
        kind == "tag",
    )
    .map_err(lookup_error)?;
    let diagnostics = scan_diagnostics(results.truncated_scans);
    let status = evidence_status(true, &diagnostics);
    let decompile = has("--decompile");
    if !json_output(args) {
        output_search_results(&results.matches, query, false, decompile);
        return Ok(status_exit(status));
    }
    let entries: Vec<Value> = results
        .matches
        .iter()
        .map(|(address, name, reason, context, pseudocode)| {
            let mut entry =
                json!({"address":format!("0x{address:x}"), "name":name, "match_type":reason});
            if !context.is_empty() {
                entry["context"] = json!(context);
            }
            if decompile && !pseudocode.is_empty() {
                entry["pseudocode"] = json!(pseudocode);
            }
            entry
        })
        .collect();
    emit(&json!({
        "schema":"rsleigh.search/v1", "status":status, "tool_version":env!("CARGO_PKG_VERSION"),
        "file":{"sha256":compute_sha256(data)},
        "query":query, "kind":kind, "match_count":entries.len(), "results":entries,
        "diagnostics":diagnostics,
        "limits":{
            "functions_searched":results.functions_searched,
            "scan_bytes_per_function":XREF_SCAN_BYTES, "truncated_scans":results.truncated_scans,
        },
    }));
    Ok(status_exit(status))
}
