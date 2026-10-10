//! Model Context Protocol server over stdio (`rsleigh --mcp`). A thin
//! transport: tool schemas are generated from the operation catalog, and each
//! call runs the same validation, worker, evidence, and failure-envelope path
//! as the CLI, returning the CLI's JSON document as the tool result.
//!
//! Messages are newline-delimited JSON-RPC 2.0 on stdin/stdout; stdout carries
//! protocol messages only. Calls run one at a time, so a cancellation arrives
//! after its call finished and is ignored; bound work with `deadline-ms`.
use super::contracts::{Flag, Kind, Operation, Role, Target};
use super::*;
use std::io::{BufRead, Write};

/// Operations exposed as tools, in addition to `capabilities`.
const TOOLS: [&str; 4] = ["agent-brief", "card", "ssa-slice", "verify-bundle"];
/// Supported protocol revisions, newest first.
const PROTOCOL_VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const INSTRUCTIONS: &str = "Static binary analysis with rsleigh. Tools mirror the \
operations in `rsleigh --capabilities`; each result is the CLI's JSON document, whose \
`status` is ok, partial (usable but incomplete evidence), or failed. Start with \
agent-brief, then card or ssa-slice on a function address. Treat pseudocode as a \
hypothesis; cite raw P-code and evidence records.";

fn operation(name: &str) -> Option<&'static Operation> {
    TOOLS
        .contains(&name)
        .then(|| contracts::OPERATIONS.iter().find(|op| op.id == name))
        .flatten()
}

fn key(flag: &Flag) -> &'static str {
    flag.name.trim_start_matches("--")
}

/// Flags a caller may set; output selection is fixed to JSON.
fn exposed(op: &Operation) -> impl Iterator<Item = &Flag> {
    op.flags.iter().filter(|f| f.role != Role::Output)
}

fn positional_key(op: &Operation) -> Option<String> {
    op.positional.map(str::to_ascii_lowercase)
}

fn property(flag: &Flag) -> Value {
    let mut schema = match flag.kind {
        Kind::Switch => json!({"type":"boolean"}),
        Kind::Count => json!({"type":"integer","minimum":0}),
        Kind::Address => json!({"type":"string","pattern":"^0[xX][0-9a-fA-F]+$"}),
        _ => json!({"type":"string"}),
    };
    if flag.repeatable {
        schema = json!({"type":"array","items":schema});
    }
    schema["description"] = json!(if flag.placeholder.is_empty() {
        flag.help.to_string()
    } else {
        format!("{} ({})", flag.help, flag.placeholder)
    });
    schema
}

fn input_schema(op: &Operation) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    match op.target {
        Target::Binary => {
            properties.insert(
                "file".into(),
                json!({"type":"string","description":"Path to the PE, ELF, or Mach-O binary"}),
            );
            required.push("file".to_string());
        }
        Target::OptionalBinary => {
            properties.insert(
                "file".into(),
                json!({"type":"string",
                    "description":"Binary the input describes; enables source-binding checks"}),
            );
        }
        Target::None => {}
    }
    if let Some(name) = positional_key(op) {
        properties.insert(
            name.clone(),
            json!({"type":"string","description":"Function name or 0x address"}),
        );
        required.push(name);
    }
    if op.mode.takes_value() {
        properties.insert(key(&op.mode).into(), property(&op.mode));
        required.push(key(&op.mode).into());
    }
    for flag in exposed(op) {
        properties.insert(key(flag).into(), property(flag));
    }
    json!({"type":"object","properties":properties,"required":required,
        "additionalProperties":false})
}

fn tools() -> Value {
    let mut tools = vec![json!({
        "name":"capabilities", "title":"Capabilities",
        "description":format!("Operation catalog, architectures, error codes, and trust model [{}]",
            capabilities::SCHEMA),
        "inputSchema":{"type":"object","properties":{},"additionalProperties":false},
        "annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,
            "openWorldHint":false},
    })];
    for op in TOOLS.iter().filter_map(|name| operation(name)) {
        let writes = op.effects.iter().any(|(e, _)| e.starts_with("writes"))
            || op.flag("--evidence-store").is_some();
        tools.push(json!({
            "name":op.id, "title":op.id,
            "description":format!("{} [{}]", op.summary, op.schema),
            "inputSchema":input_schema(op),
            "annotations":{"readOnlyHint":!writes,"destructiveHint":false,"idempotentHint":true,
                "openWorldHint":false},
        }));
    }
    json!({"tools":tools})
}

fn invalid(message: impl Into<String>) -> AgentError {
    AgentError::new("invalid_value", message)
}

fn push_value(argv: &mut Vec<String>, flag: &Flag, value: &Value) -> Result<(), AgentError> {
    let name = key(flag);
    let scalar = |v: &Value| match (flag.kind, v) {
        (Kind::Count, Value::Number(n)) if n.is_u64() => Ok(n.to_string()),
        (Kind::Count, _) => Err(invalid(format!("{name} must be a non-negative integer"))),
        (_, Value::String(s)) => Ok(s.clone()),
        _ => Err(invalid(format!("{name} must be a string"))),
    };
    match (flag.kind, value) {
        (_, Value::Null) | (Kind::Switch, Value::Bool(false)) => {}
        (Kind::Switch, Value::Bool(true)) => argv.push(flag.name.into()),
        (Kind::Switch, _) => return Err(invalid(format!("{name} must be a boolean"))),
        (_, Value::Array(items)) if flag.repeatable => {
            for item in items {
                argv.extend([flag.name.to_string(), scalar(item)?]);
            }
        }
        _ if flag.repeatable => return Err(invalid(format!("{name} must be an array"))),
        _ => argv.extend([flag.name.to_string(), scalar(value)?]),
    }
    Ok(())
}

/// The CLI argv for a tool call, and whether it names no target binary.
fn argv(
    op: &Operation,
    arguments: &serde_json::Map<String, Value>,
) -> Result<(Vec<String>, bool), AgentError> {
    let positional = positional_key(op);
    let mode_key = op.mode.takes_value().then(|| key(&op.mode));
    let known = |name: &str| {
        (name == "file" && op.target != Target::None)
            || positional.as_deref() == Some(name)
            || mode_key == Some(name)
            || exposed(op).any(|f| key(f) == name)
    };
    if let Some(extra) = arguments.keys().find(|k| !known(k)) {
        return Err(AgentError::new(
            "unsupported_option",
            format!("unsupported {} argument: {extra}", op.id),
        ));
    }
    let text = |name: &str| match arguments.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(invalid(format!("{name} must be a string"))),
    };
    let mut argv = vec!["rsleigh".to_string()];
    let file = text("file")?;
    if op.target == Target::Binary && file.is_none() {
        return Err(AgentError::new("invalid_target", "file is required"));
    }
    let target_free = file.is_none();
    if let Some(file) = file {
        // Never let a path read as an option.
        argv.push(if file.starts_with('-') {
            format!("./{file}")
        } else {
            file
        });
    }
    if let Some(name) = &positional {
        argv.push(
            text(name)?
                .ok_or_else(|| AgentError::new("missing_value", format!("{name} is required")))?,
        );
    }
    argv.push(op.mode.name.into());
    if let Some(name) = mode_key {
        let value = arguments
            .get(name)
            .filter(|v| !v.is_null())
            .ok_or_else(|| AgentError::new("missing_value", format!("{name} is required")))?;
        let mut pair = Vec::new();
        push_value(&mut pair, &op.mode, value)?;
        argv.extend(pair.into_iter().skip(1));
    }
    for flag in exposed(op) {
        if let Some(value) = arguments.get(key(flag)) {
            push_value(&mut argv, flag, value)?;
        }
    }
    if op.flag("--json").is_some() {
        argv.push("--json".into());
    }
    Ok((argv, target_free))
}

fn tool_result(code: u8, mut output: Vec<Value>) -> Value {
    let document = if output.len() == 1 && output[0].is_object() {
        output.remove(0)
    } else {
        json!({"results":output})
    };
    json!({
        "content":[{"type":"text","text":serde_json::to_string(&document).expect("JSON value is serializable")}],
        "structuredContent":document,
        "isError":code == 1,
    })
}

fn call(params: &Value) -> Result<Value, (i64, String)> {
    let name = params["name"]
        .as_str()
        .ok_or((-32602, "tools/call requires a tool name".to_string()))?;
    let arguments = match &params["arguments"] {
        Value::Null => serde_json::Map::new(),
        Value::Object(map) => map.clone(),
        _ => return Err((-32602, "tool arguments must be an object".into())),
    };
    if name == "capabilities" {
        if let Some(extra) = arguments.keys().next() {
            let error = AgentError::new(
                "unsupported_option",
                format!("unsupported capabilities argument: {extra}"),
            );
            return Ok(tool_result(
                1,
                vec![failure_envelope(capabilities::SCHEMA, &error)],
            ));
        }
        let args = ["rsleigh", "--capabilities", "--json"]
            .map(str::to_string)
            .to_vec();
        let (code, output) = invoke(Vec::new(), args, true, true);
        return Ok(tool_result(code, output));
    }
    let op = operation(name).ok_or_else(|| (-32602, format!("Unknown tool: {name}")))?;
    Ok(match argv(op, &arguments) {
        Ok((args, target_free)) => {
            let (code, output) = invoke(vec![op], args, target_free, true);
            tool_result(code, output)
        }
        Err(error) => tool_result(1, vec![failure_envelope(op.schema, &error)]),
    })
}

/// Response to one message, or None for notifications and client responses.
fn handle(line: &[u8]) -> Option<Value> {
    let error = |id: Value, code: i64, message: &str| {
        Some(json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}))
    };
    let message: Value = match serde_json::from_slice(line) {
        Ok(message) => message,
        Err(_) => return error(Value::Null, -32700, "Parse error"),
    };
    let Some(object) = message.as_object() else {
        return error(
            Value::Null,
            -32600,
            "Invalid Request: expected one JSON-RPC object",
        );
    };
    let id = object.get("id").cloned();
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        // A response to a server request; this server sends none.
        return match id {
            Some(_) if !object.contains_key("result") && !object.contains_key("error") => error(
                id.unwrap_or_default(),
                -32600,
                "Invalid Request: missing method",
            ),
            _ => None,
        };
    };
    // Notifications (initialized, cancelled, ...) need no response.
    let id = id?;
    if !(id.is_string() || id.is_i64() || id.is_u64()) {
        return error(
            Value::Null,
            -32600,
            "Invalid Request: id must be a string or integer",
        );
    }
    let params = object.get("params").cloned().unwrap_or(Value::Null);
    let result = match method {
        "initialize" => {
            let requested = params["protocolVersion"].as_str().unwrap_or("");
            let version = PROTOCOL_VERSIONS
                .iter()
                .find(|v| **v == requested)
                .unwrap_or(&PROTOCOL_VERSIONS[0]);
            Ok(json!({
                "protocolVersion":version,
                "capabilities":{"tools":{"listChanged":false}},
                "serverInfo":{"name":"rsleigh","title":"rsleigh","version":env!("CARGO_PKG_VERSION")},
                "instructions":INSTRUCTIONS,
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(tools()),
        "tools/call" => call(&params),
        _ => Err((-32601, format!("Method not found: {method}"))),
    };
    Some(match result {
        Ok(result) => json!({"jsonrpc":"2.0","id":id,"result":result}),
        Err((code, message)) => {
            json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
        }
    })
}

/// Serve until stdin closes. Stdout is locked only while writing a message so
/// a worker thread can never block on it.
pub(super) fn serve() -> Result<u8, AgentError> {
    let mut input = std::io::stdin().lock();
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = input
            .read_until(b'\n', &mut line)
            .map_err(|e| AgentError::new("input_unreadable", format!("cannot read stdin: {e}")))?;
        if read == 0 {
            return Ok(0);
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if let Some(response) = handle(&line) {
            let mut out = std::io::stdout().lock();
            writeln!(out, "{response}")
                .and_then(|_| out.flush())
                .map_err(|e| {
                    AgentError::new("write_failed", format!("cannot write stdout: {e}"))
                })?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str) -> Value {
        tools()["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == name)
            .unwrap()
            .clone()
    }

    #[test]
    fn schemas_follow_the_catalog() {
        let card = tool("card");
        let schema = &card["inputSchema"];
        assert_eq!(schema["required"], json!(["file", "function"]));
        assert_eq!(schema["properties"]["pcode"]["type"], "boolean");
        assert_eq!(schema["properties"]["deadline-ms"]["type"], "integer");
        assert_eq!(schema["properties"]["derived-from"]["type"], "array");
        assert!(schema["properties"].get("json").is_none());
        assert_eq!(card["annotations"]["readOnlyHint"], false);
        let slice = tool("ssa-slice");
        assert_eq!(
            slice["inputSchema"]["required"],
            json!(["file", "ssa-slice"])
        );
        let verify = tool("verify-bundle");
        assert_eq!(verify["inputSchema"]["required"], json!(["verify-bundle"]));
        assert_eq!(verify["annotations"]["readOnlyHint"], true);
    }

    #[test]
    fn arguments_become_validated_argv() {
        let card = operation("card").unwrap();
        let args = |v: Value| v.as_object().unwrap().clone();
        let (built, target_free) = argv(
            card,
            &args(json!({"file":"-a.exe","function":"0x401000","pcode":true,
                "decompile":false,"max-ssa-work":10,"derived-from":["sha256:00"]})),
        )
        .unwrap();
        assert!(!target_free);
        assert_eq!(
            built,
            [
                "rsleigh",
                "./-a.exe",
                "0x401000",
                "--card",
                "--pcode",
                "--max-ssa-work",
                "10",
                "--derived-from",
                "sha256:00",
                "--json"
            ]
        );
        for bad in [
            json!({"file":"a","function":"f","cache":"/tmp"}),
            json!({"file":"a","function":"f","pcode":"yes"}),
            json!({"file":"a","function":"f","max-ssa-work":-1}),
            json!({"file":"a","function":"f","derived-from":"sha256:00"}),
            json!({"function":"f"}),
            json!({"file":"a"}),
        ] {
            assert!(argv(card, &args(bad.clone())).is_err(), "{bad}");
        }
        let verify = operation("verify-bundle").unwrap();
        let (built, target_free) = argv(verify, &args(json!({"verify-bundle":"b"}))).unwrap();
        assert!(target_free);
        assert_eq!(built, ["rsleigh", "--verify-bundle", "b", "--json"]);
    }

    #[test]
    fn protocol_errors_and_notifications() {
        assert_eq!(handle(b"{").unwrap()["error"]["code"], -32700);
        assert_eq!(handle(b"[]").unwrap()["error"]["code"], -32600);
        assert!(handle(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).is_none());
        assert_eq!(
            handle(br#"{"jsonrpc":"2.0","id":1,"method":"nope"}"#).unwrap()["error"]["code"],
            -32601
        );
        assert_eq!(
            handle(br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"index"}}"#)
                .unwrap()["error"]["code"],
            -32602
        );
        let init = handle(
            br#"{"jsonrpc":"2.0","id":"a","method":"initialize","params":{"protocolVersion":"1999-01-01"}}"#,
        )
        .unwrap();
        assert_eq!(init["id"], "a");
        assert_eq!(init["result"]["protocolVersion"], PROTOCOL_VERSIONS[0]);
    }
}
