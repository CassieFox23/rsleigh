//! `rsleigh --mcp`: a stdio session must speak only JSON-RPC on stdout and
//! return the same documents, evidence IDs, and failure codes as the CLI.
use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const RSLEIGH_BIN: &str = env!("CARGO_BIN_EXE_rsleigh");

#[path = "../../test-harness/fixtures/agent-re/seed.rs"]
mod seed;

fn scratch() -> PathBuf {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("rsleigh-agent-mcp-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn cli(args: &[&str]) -> (i32, Value) {
    let output = Command::new(RSLEIGH_BIN)
        .args(args)
        .env_remove("RSLEIGH_OPAQUE_FOLD")
        .output()
        .unwrap();
    let value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{args:?}: {}", String::from_utf8_lossy(&output.stdout)));
    (output.status.code().unwrap(), value)
}

/// Send every message, close stdin, and return responses by ID. Every stdout
/// line must be a JSON-RPC 2.0 response.
fn session(messages: &[Value]) -> (i32, std::collections::BTreeMap<String, Value>) {
    let mut child = Command::new(RSLEIGH_BIN)
        .arg("--mcp")
        .env_remove("RSLEIGH_OPAQUE_FOLD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for message in messages {
        writeln!(stdin, "{message}").unwrap();
    }
    writeln!(stdin, "{{not json").unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    let mut responses = std::collections::BTreeMap::new();
    for line in String::from_utf8(output.stdout).unwrap().lines() {
        let response: Value =
            serde_json::from_str(line).unwrap_or_else(|_| panic!("non-protocol stdout: {line}"));
        assert_eq!(response["jsonrpc"], "2.0", "{line}");
        assert!(
            response.get("result").is_some() != response.get("error").is_some(),
            "{line}"
        );
        let id = match &response["id"] {
            Value::Null => "null".to_string(),
            id => id.to_string(),
        };
        assert!(
            responses.insert(id, response).is_none(),
            "duplicate response"
        );
    }
    (output.status.code().unwrap(), responses)
}

fn request(id: u64, method: &str, params: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
}

fn call(id: u64, name: &str, arguments: Value) -> Value {
    request(id, "tools/call", json!({"name":name,"arguments":arguments}))
}

/// Remove execution-only fields (timings, cache counters) before comparing.
fn observation(mut value: Value) -> Value {
    fn strip(value: &mut Value) {
        match value {
            Value::Object(map) => {
                map.remove("metrics");
                map.values_mut().for_each(strip);
            }
            Value::Array(items) => items.iter_mut().for_each(strip),
            _ => {}
        }
    }
    strip(&mut value);
    value
}

#[test]
fn stdio_session_matches_cli_contract() {
    let root = scratch();
    let binary = root.join("seed.exe");
    std::fs::write(&binary, seed::binary()).unwrap();
    let (mcp_store, cli_store) = (root.join("mcp-store"), root.join("cli-store"));
    let file = s(&binary);

    let (code, responses) = session(&[
        request(
            1,
            "initialize",
            json!({"protocolVersion":"2025-06-18",
            "capabilities":{},"clientInfo":{"name":"test","version":"0"}}),
        ),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        request(2, "tools/list", json!({})),
        request(3, "ping", json!({})),
        call(4, "agent-brief", json!({"file":file,"limit":2})),
        call(
            5,
            "card",
            json!({"file":file,"function":"0x401000","pcode":true,
            "evidence-store":s(&mcp_store)}),
        ),
        call(
            6,
            "ssa-slice",
            json!({"file":file,"ssa-slice":"0x401060","return":true}),
        ),
        call(
            7,
            "card",
            json!({"file":file,"function":"no_such_function"}),
        ),
        call(
            8,
            "card",
            json!({"file":file,"function":"0x401000","cache":"/tmp"}),
        ),
        call(
            9,
            "verify-bundle",
            json!({"verify-bundle":s(&root.join("missing"))}),
        ),
        call(10, "capabilities", json!({})),
        call(11, "index", json!({"file":file})),
        call(12, "xrefs", json!({"file":file,"xrefs":"helper"})),
        call(
            13,
            "search",
            json!({"file":file,"query":"helper","api":true}),
        ),
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":4}}),
    ]);
    assert_eq!(code, 0, "server exits cleanly when stdin closes");
    assert_eq!(responses.len(), 14, "13 requests plus one parse error");
    assert_eq!(responses["null"]["error"]["code"], -32700);

    let init = &responses["1"]["result"];
    assert_eq!(init["protocolVersion"], "2025-06-18");
    assert_eq!(init["capabilities"]["tools"]["listChanged"], false);
    let tools: Vec<&str> = responses["2"]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        tools,
        [
            "capabilities",
            "agent-brief",
            "card",
            "xrefs",
            "search",
            "ssa-slice",
            "verify-bundle"
        ]
    );
    assert_eq!(responses["3"]["result"], json!({}));
    assert_eq!(
        responses["11"]["error"]["code"], -32602,
        "index is not exposed"
    );

    let result = |id: &str| -> (bool, Value) {
        let result = &responses[id]["result"];
        let text: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(
            text, result["structuredContent"],
            "text mirrors structured content"
        );
        (result["isError"].as_bool().unwrap(), text)
    };

    // Same documents as the CLI.
    let (error, brief) = result("4");
    assert!(!error);
    let (_, expected) = cli(&[file, "--agent-brief", "--limit", "2", "--json"]);
    assert_eq!(observation(brief), observation(expected));
    let (_, slice) = result("6");
    let (_, expected) = cli(&[file, "--ssa-slice", "0x401060", "--return", "--json"]);
    assert_eq!(observation(slice), observation(expected));

    // Evidence through MCP has the same content ID as through the CLI.
    let (error, record) = result("5");
    assert!(!error);
    assert_eq!(record["schema"], "rsleigh.evidence/v1");
    let (code, expected) = cli(&[
        file,
        "0x401000",
        "--card",
        "--pcode",
        "--json",
        "--evidence-store",
        s(&cli_store),
    ]);
    assert_eq!(code, 0);
    assert_eq!(record["id"], expected["id"]);

    // Failures keep the CLI envelope and error codes.
    let (error, failed) = result("7");
    assert!(error);
    let (code, expected) = cli(&[file, "no_such_function", "--card", "--json"]);
    assert_eq!(code, 1);
    assert_eq!(failed["error_code"], expected["error_code"]);
    let (error, rejected) = result("8");
    assert!(error);
    assert_eq!(rejected["error_code"], "unsupported_option");
    let (error, missing) = result("9");
    assert!(error);
    assert_eq!(missing["status"], "failed");
    for (id, argv) in [
        ("12", vec![file, "--xrefs", "helper", "--json"]),
        ("13", vec![file, "helper", "--search", "--api", "--json"]),
    ] {
        let (error, document) = result(id);
        assert!(!error);
        let (code, expected) = cli(&argv);
        assert_eq!(code, 0);
        assert_eq!(document, expected, "{argv:?}");
    }
    let (error, catalog) = result("10");
    assert!(!error);
    assert_eq!(catalog["schema"], "rsleigh.capabilities/v1");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn mcp_mode_takes_no_arguments() {
    let (code, value) = cli(&["--mcp", "--json"]);
    assert_eq!(code, 1);
    assert_eq!(value["error_code"], "unsupported_option");
}
