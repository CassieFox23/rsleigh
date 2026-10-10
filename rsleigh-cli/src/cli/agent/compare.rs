//! Structured function comparison. Bytes, instructions, calls, strings, CFG,
//! and pseudocode are compared separately and each reports `changed`,
//! `unchanged`, or `unknown`. Missing, partial, or incompatible analysis is
//! never reported as `unchanged`, and an absent function is only `absent`
//! when the other side's inventory is complete. This compares evidence; it
//! does not prove semantic equivalence.
use super::*;
use pcode_ir::{AddressSpaceId, PcodeOp};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub(super) const SCHEMA: &str = "rsleigh.function-comparison/v1";
const DEFAULT_PAIRS: usize = 100;
pub(super) const MAX_PAIRS: usize = 10_000;
/// LCS cells allowed before a pseudocode line diff is omitted.
const MAX_LCS_CELLS: usize = 2_000_000;
const MAX_DIFF_LINES: usize = 400;
/// Function decoding stops after this many bytes (see decode_func_*).
const DECODE_WINDOW: u64 = 4096;
const MAX_SUGGESTION_CANDIDATES: usize = 500;
const DIMENSIONS: [&str; 6] = [
    "bytes",
    "instructions",
    "calls",
    "strings",
    "cfg",
    "pseudocode",
];
/// Dimensions whose representation depends on architecture and convention.
const REPRESENTATION: [&str; 5] = ["instructions", "calls", "strings", "cfg", "pseudocode"];

fn is_generic(name: &str) -> bool {
    name.is_empty()
        || ["FUN_", "func_", "sub_", "LAB_"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

/// One parsed input. `data` outlives the borrowed container.
struct Side<'a> {
    label: &'static str,
    path: &'a str,
    data: &'a [u8],
    obj: goblin::Object<'a>,
    arch: rsleigh_api::Architecture,
    segs: Vec<(u64, u64, u64)>,
    symbols: Vec<(u64, String)>,
    imports: HashMap<u64, String>,
    names: HashMap<u64, String>,
    by_name: BTreeMap<String, Vec<u64>>,
    image: (u64, u64),
    inventory: Value,
    inventory_complete: bool,
    /// Matched function entry → pair index; a justified cross-binary mapping.
    pairs: HashMap<u64, usize>,
    /// Names unique on both sides: the only symbols that identify a location
    /// across binaries. Other names are unresolved references.
    shared: BTreeSet<String>,
}

impl<'a> Side<'a> {
    fn load(label: &'static str, path: &'a str, data: &'a [u8]) -> Result<Self, AgentError> {
        let (obj, arch, segs, symbols) = parse_native(data)?;
        let imports = build_import_map(&obj, data);
        let mut names = HashMap::new();
        let mut by_name: BTreeMap<String, Vec<u64>> = BTreeMap::new();
        for (address, name) in &symbols {
            names.entry(*address).or_insert_with(|| name.clone());
            by_name.entry(name.clone()).or_default().push(*address);
        }
        let image = (
            segs.iter().map(|(va, _, _)| *va).min().unwrap_or(0),
            segs.iter()
                .map(|(va, size, _)| va + size)
                .max()
                .unwrap_or(0),
        );
        // Only an unstripped ELF symbol table enumerates every function. PE
        // exports, Mach-O stubs, and discovery are partial inventories.
        let (basis, complete) = match &obj {
            goblin::Object::Elf(elf)
                if !elf.syms.is_empty() && symbols.iter().any(|(_, n)| !is_generic(n)) =>
            {
                ("symbol_table", true)
            }
            goblin::Object::Elf(_) => ("heuristic_discovery", false),
            goblin::Object::PE(_) => ("exports_and_discovery", false),
            _ => ("symbols_and_discovery", false),
        };
        let (format, imagebase) = agent_format_and_base(&obj, &segs);
        let inventory = json!({"functions":symbols.len(),"basis":basis,"complete":complete});
        let file = json!({"path":path,"sha256":compute_sha256(data),"format":format,
            "arch":format!("{arch:?}"),"imagebase":format!("0x{imagebase:x}"),
            "calling_convention":agent_calling_convention(arch, &obj)});
        let mut side = Self {
            label,
            path,
            data,
            obj,
            arch,
            segs,
            symbols,
            imports,
            names,
            by_name,
            image,
            inventory_complete: complete,
            inventory: json!({"file":file,"inventory":inventory}),
            pairs: HashMap::new(),
            shared: BTreeSet::new(),
        };
        side.inventory["file"]["path"] = json!(side.path);
        Ok(side)
    }

    fn name(&self, address: u64) -> String {
        self.names
            .get(&address)
            .cloned()
            .unwrap_or_else(|| format!("FUN_{address:x}"))
    }

    fn convention(&self) -> &'static str {
        agent_calling_convention(self.arch, &self.obj)
    }

    /// Normalized location token: function-relative inside the function,
    /// otherwise an import, matched pair, or non-generic symbol. Anything
    /// else is unresolved and only compared after masking.
    fn locate(&self, range: (u64, u64), address: u64) -> (String, bool) {
        if address >= range.0 && address < range.1 {
            (format!("self+0x{:x}", address - range.0), true)
        } else if let Some(import) = self.imports.get(&address) {
            (format!("import:{import}"), true)
        } else if let Some(index) = self.pairs.get(&address) {
            (format!("pair:{index}"), true)
        } else if let Some(name) = self.names.get(&address).filter(|n| !is_generic(n)) {
            (format!("sym:{name}"), self.shared.contains(name))
        } else {
            (format!("ext:0x{address:x}"), false)
        }
    }

    fn in_image(&self, address: u64) -> bool {
        address >= self.image.0 && address < self.image.1
    }

    fn bytes(&self, address: u64, len: u64) -> Option<&[u8]> {
        self.segs.iter().find_map(|(va, size, offset)| {
            let delta = address.checked_sub(*va)?;
            if delta.checked_add(len)? > *size {
                return None;
            }
            let start = usize::try_from(offset.checked_add(delta)?).ok()?;
            self.data.get(start..start.checked_add(len as usize)?)
        })
    }
}

/// Exact and masked token sequences: masking hides unresolved references so a
/// difference that exists only there is reported as unknown, not changed.
#[derive(Default, PartialEq)]
struct Tokens {
    exact: Vec<String>,
    masked: Vec<String>,
}

impl Tokens {
    fn push(&mut self, exact: String, masked: String) {
        self.exact.push(exact);
        self.masked.push(masked);
    }
}

struct Facts {
    name: String,
    address: u64,
    decoded: bool,
    /// Decode/decompile finished and the decode window was not exhausted.
    complete: bool,
    /// Every body instruction was found from the entry (no indirect jumps).
    reachability_complete: bool,
    diagnostics: Vec<Value>,
    bytes: Vec<u8>,
    instructions: Tokens,
    calls: Tokens,
    indirect_calls: usize,
    cfg: Tokens,
    strings: BTreeSet<String>,
    pseudocode: Option<Tokens>,
    body_instructions: usize,
}

type Decoded = (u64, pcode_ir::Instruction);

/// Reachable function body.
struct Body {
    /// Indices into the decoded instructions, in address order.
    indices: Vec<usize>,
    /// No indirect jump, misaligned target, or undecoded in-function target.
    reachability_complete: bool,
    /// Control falls past the last decoded instruction.
    falls_off_end: bool,
}

/// Instructions reachable from the entry along fallthrough and direct
/// branches. Unreachable padding before `limit` (the next function) is
/// excluded, so its decode failures do not make the function incomplete.
fn body(instructions: &[Decoded], limit: u64) -> Body {
    let index: HashMap<u64, usize> = instructions
        .iter()
        .enumerate()
        .map(|(i, (address, _))| (*address, i))
        .collect();
    let start = instructions.first().map(|(a, _)| *a).unwrap_or(0);
    let mut result = Body {
        indices: vec![],
        reachability_complete: true,
        falls_off_end: false,
    };
    let mut seen = BTreeSet::new();
    let mut pending = vec![0usize];
    while let Some(i) = pending.pop() {
        if i >= instructions.len() || !seen.insert(i) {
            continue;
        }
        let (address, inst) = &instructions[i];
        let (mut conditional, mut terminates) = (false, false);
        for op in &inst.ops {
            let target = match op {
                PcodeOp::Branch { dest } => {
                    terminates = true;
                    Some(dest)
                }
                PcodeOp::CBranch { dest, .. } => {
                    conditional = true;
                    Some(dest)
                }
                PcodeOp::BranchInd { .. } => {
                    terminates = true;
                    result.reachability_complete = false;
                    None
                }
                PcodeOp::Return { .. } => {
                    terminates = true;
                    None
                }
                _ => None,
            };
            if let Some(dest) = target.filter(|d| d.space == AddressSpaceId::Ram) {
                match index.get(&dest.offset) {
                    Some(&j) => pending.push(j),
                    None if dest.offset >= start && dest.offset < limit => {
                        result.reachability_complete = false
                    }
                    None => {}
                }
            }
        }
        if !terminates || conditional {
            match instructions.get(i + 1) {
                Some((next, _)) if *next == address + inst.len => pending.push(i + 1),
                Some(_) => result.reachability_complete = false,
                None => result.falls_off_end = true,
            }
        }
    }
    result.indices = seen.into_iter().collect();
    result
}

/// Rewrite varnodes in one instruction's typed operations. Addresses
/// become location tokens and instruction-local temporaries (whose offsets
/// encode the instruction address) are renumbered in order of appearance.
fn normalize_ops(side: &Side, range: (u64, u64), ops: &Value, masked: bool) -> Value {
    fn walk(
        side: &Side,
        range: (u64, u64),
        value: &Value,
        masked: bool,
        temporaries: &mut HashMap<u64, usize>,
    ) -> Value {
        match value {
            Value::Object(map) if map.contains_key("space") && map.contains_key("offset") => {
                let offset = map["offset"].as_u64().unwrap_or(0);
                match map["space"].as_str().unwrap_or("") {
                    "Unique" => {
                        let next = temporaries.len();
                        let n = *temporaries.entry(offset).or_insert(next);
                        json!({"space":"Unique","temp":n,"size":map["size"]})
                    }
                    space @ ("Ram" | "Const") if space == "Ram" || side.in_image(offset) => {
                        let (token, resolved) = side.locate(range, offset);
                        let token = if masked && !resolved {
                            "?".to_string()
                        } else {
                            token
                        };
                        json!({"space":space,"loc":token,"size":map["size"]})
                    }
                    _ => value.clone(),
                }
            }
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(k, v)| (k.clone(), walk(side, range, v, masked, temporaries)))
                    .collect(),
            ),
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|v| walk(side, range, v, masked, temporaries))
                    .collect(),
            ),
            other => other.clone(),
        }
    }
    walk(side, range, ops, masked, &mut HashMap::new())
}

/// Normalize pseudocode: the function's own name, address-derived labels,
/// and image addresses become location tokens before lines are compared.
fn normalize_text(side: &Side, range: (u64, u64), own: &str, text: &str) -> Tokens {
    let mut tokens = Tokens::default();
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let (mut exact, mut masked) = (String::new(), String::new());
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if c.is_ascii_alphanumeric() || c == '_' {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                let address = word
                    .strip_prefix("0x")
                    .or_else(|| {
                        ["FUN_", "LAB_", "DAT_", "PTR_", "sub_", "func_0x"]
                            .iter()
                            .find_map(|p| word.strip_prefix(p))
                    })
                    .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                    .filter(|a| side.in_image(*a) || (*a >= range.0 && *a < range.1));
                if word == own {
                    exact.push_str("FUNCTION");
                    masked.push_str("FUNCTION");
                } else if let Some(address) = address {
                    let (token, resolved) = side.locate(range, address);
                    masked.push_str(if resolved { &token } else { "?" });
                    exact.push_str(&token);
                } else {
                    exact.push_str(&word);
                    masked.push_str(&word);
                }
            } else {
                exact.push(c);
                masked.push(c);
                i += 1;
            }
        }
        tokens.push(exact, masked);
    }
    tokens
}

fn facts(side: &Side, address: u64) -> Facts {
    let name = side.name(address);
    let mut facts = Facts {
        name: name.clone(),
        address,
        decoded: false,
        complete: false,
        reachability_complete: false,
        diagnostics: vec![],
        bytes: vec![],
        instructions: Tokens::default(),
        calls: Tokens::default(),
        indirect_calls: 0,
        cfg: Tokens::default(),
        strings: BTreeSet::new(),
        pseudocode: None,
        body_instructions: 0,
    };
    let mut decode_diagnostics = vec![];
    let instructions = decode_func_raw_with_diagnostics(
        address,
        &side.symbols,
        &side.segs,
        side.data,
        &mut rsleigh_api::Decoder::new(side.arch),
        &mut decode_diagnostics,
    );
    if instructions.is_empty() {
        facts.diagnostics = decode_diagnostics;
        facts.diagnostics.push(diagnostic(
            "decode",
            "no_instructions",
            "no decodable instructions",
        ));
        return facts;
    }
    facts.decoded = true;
    let limit = side
        .symbols
        .iter()
        .map(|(a, _)| *a)
        .filter(|a| *a > address)
        .min()
        .unwrap_or(address + DECODE_WINDOW)
        .min(address + DECODE_WINDOW);
    let reach = body(&instructions, limit);
    let body = reach.indices;
    facts.reachability_complete = reach.reachability_complete;
    facts.body_instructions = body.len();
    let end = instructions
        .last()
        .map(|(a, i)| a + i.len)
        .unwrap_or(address);
    // Decode failures only matter if the body runs into them; failures in
    // unreachable padding are reported but do not truncate the function.
    let truncated = reach.falls_off_end
        && (!decode_diagnostics.is_empty() || end < limit || end - address + 16 >= DECODE_WINDOW);
    for mut diagnostic in decode_diagnostics {
        diagnostic["affects_body"] = json!(truncated);
        facts.diagnostics.push(diagnostic);
    }
    if truncated {
        facts.diagnostics.push(diagnostic(
            "decode",
            "body_truncated",
            "reachable code continues past the decoded instructions",
        ));
    }
    let body_instructions: Vec<Decoded> = body.iter().map(|&i| instructions[i].clone()).collect();
    let mut decompile_diagnostics = vec![];
    let pseudocode = recover_decompile(
        || {
            rsleigh_decompile::decompile_with_binary(
                side.arch,
                &body_instructions,
                Some(side.data),
                Some(Path::new(side.path)),
            )
        },
        &mut decompile_diagnostics,
    );
    facts.complete = !truncated && decompile_diagnostics.is_empty();
    facts.diagnostics.extend(decompile_diagnostics);
    let range = (
        address,
        body.iter()
            .map(|&i| instructions[i].0 + instructions[i].1.len)
            .max()
            .unwrap_or(address),
    );
    let mut leaders = BTreeSet::from([body[0]]);
    let mut calls = BTreeMap::<String, String>::new();
    for (position, &i) in body.iter().enumerate() {
        let (inst_address, inst) = &instructions[i];
        match side.bytes(*inst_address, inst.len) {
            Some(bytes) => facts.bytes.extend_from_slice(bytes),
            None => facts.complete = false,
        }
        let ops = serde_json::to_value(&inst.ops).unwrap_or(Value::Null);
        facts.instructions.push(
            normalize_ops(side, range, &ops, false).to_string(),
            normalize_ops(side, range, &ops, true).to_string(),
        );
        let mut ends_block = false;
        for op in &inst.ops {
            match op {
                PcodeOp::Call { dest } if dest.space == AddressSpaceId::Ram => {
                    let (token, resolved) = side.locate(range, dest.offset);
                    let masked = if resolved { token.clone() } else { "?".into() };
                    calls.insert(token, masked);
                }
                PcodeOp::CallInd { .. } => facts.indirect_calls += 1,
                PcodeOp::Branch { dest } | PcodeOp::CBranch { dest, .. }
                    if dest.space == AddressSpaceId::Ram =>
                {
                    ends_block = true;
                    if let Ok(j) = instructions.binary_search_by_key(&dest.offset, |x| x.0) {
                        leaders.insert(j);
                    }
                }
                PcodeOp::BranchInd { .. } | PcodeOp::Return { .. } => ends_block = true,
                _ => {}
            }
        }
        let contiguous = body
            .get(position + 1)
            .is_some_and(|&next| instructions[next].0 == inst_address + inst.len);
        if let Some(&next) = body.get(position + 1) {
            if ends_block || !contiguous {
                leaders.insert(next);
            }
        }
    }
    for (exact, masked) in calls {
        facts.calls.push(exact, masked);
    }
    // CFG shape: blocks in address order with successor block indices,
    // returns, indirect jumps, and exits; independent of block sizes.
    let block_of: HashMap<usize, usize> =
        leaders.iter().enumerate().map(|(b, &i)| (i, b)).collect();
    let leaders: Vec<usize> = leaders.into_iter().collect();
    for (b, &leader) in leaders.iter().enumerate() {
        let last = body
            .iter()
            .copied()
            .filter(|&i| i >= leader && leaders.get(b + 1).is_none_or(|&n| i < n))
            .max()
            .unwrap_or(leader);
        let (inst_address, inst) = &instructions[last];
        let (mut exact, mut masked) = (vec![], vec![]);
        let (mut terminates, mut conditional) = (false, false);
        for op in &inst.ops {
            let edge = match op {
                PcodeOp::Branch { dest } | PcodeOp::CBranch { dest, .. }
                    if dest.space == AddressSpaceId::Ram =>
                {
                    if matches!(op, PcodeOp::Branch { .. }) {
                        terminates = true;
                    } else {
                        conditional = true;
                    }
                    Some(
                        match block_of.get(
                            &instructions
                                .binary_search_by_key(&dest.offset, |x| x.0)
                                .unwrap_or(usize::MAX),
                        ) {
                            Some(target) => (format!("b{target}"), true),
                            None => {
                                let (token, resolved) = side.locate(range, dest.offset);
                                (format!("out:{token}"), resolved)
                            }
                        },
                    )
                }
                PcodeOp::CBranch { .. } => {
                    conditional = true;
                    None
                }
                PcodeOp::Return { .. } => {
                    terminates = true;
                    Some(("ret".into(), true))
                }
                PcodeOp::BranchInd { .. } => {
                    terminates = true;
                    Some(("indirect".into(), true))
                }
                _ => None,
            };
            if let Some((token, resolved)) = edge {
                masked.push(if resolved { token.clone() } else { "?".into() });
                exact.push(token);
            }
        }
        if !terminates || conditional {
            if let Some(next) = leaders.get(b + 1) {
                if body.contains(next) && instructions[*next].0 == inst_address + inst.len {
                    exact.push(format!("b{}", b + 1));
                    masked.push(format!("b{}", b + 1));
                }
            }
        }
        facts.cfg.push(exact.join(","), masked.join(","));
    }
    if !pseudocode.is_empty() {
        facts.strings =
            rsleigh_decompile::analysis::extract_function_meta(&name, address, &pseudocode)
                .strings
                .into_iter()
                .collect();
        facts.pseudocode = Some(normalize_text(side, range, &name, &pseudocode));
    }
    facts
}

fn dimension(result: &str, reason: Option<&str>, detail: Value) -> Value {
    json!({"result":result,"reason":reason,"detail":detail})
}

/// Compare token sequences. Equal complete evidence is unchanged; a
/// difference visible in both decoded prefixes is changed; differences only
/// in unresolved references or beyond incomplete evidence are unknown.
fn compare_tokens(
    old: &Tokens,
    new: &Tokens,
    complete: bool,
) -> (&'static str, Option<&'static str>, Value) {
    let first = |a: &[String], b: &[String]| a.iter().zip(b).position(|(x, y)| x != y);
    if old.exact == new.exact {
        return if complete {
            ("unchanged", None, json!({"items":old.exact.len()}))
        } else {
            (
                "unknown",
                Some("incomplete_analysis"),
                json!({"items":old.exact.len()}),
            )
        };
    }
    if old.masked == new.masked {
        return (
            "unknown",
            Some("unmapped_reference"),
            json!({"items":old.exact.len()}),
        );
    }
    let detail = json!({"old_items":old.exact.len(),"new_items":new.exact.len(),
        "first_difference":first(&old.masked, &new.masked)});
    if complete || first(&old.masked, &new.masked).is_some() {
        ("changed", None, detail)
    } else {
        ("unknown", Some("incomplete_analysis"), detail)
    }
}

/// Bounded line diff over normalized pseudocode. Returns None when the LCS
/// table would exceed MAX_LCS_CELLS; the caller reports the omission.
fn line_diff(old: &[String], new: &[String]) -> Option<Vec<(char, String)>> {
    let (m, n) = (old.len(), new.len());
    if (m + 1).saturating_mul(n + 1) > MAX_LCS_CELLS {
        return None;
    }
    let mut dp = vec![vec![0u32; n + 1]; m + 1];
    for i in 1..=m {
        for j in 1..=n {
            dp[i][j] = if old[i - 1] == new[j - 1] {
                dp[i - 1][j - 1] + 1
            } else {
                dp[i - 1][j].max(dp[i][j - 1])
            };
        }
    }
    let (mut i, mut j, mut out) = (m, n, Vec::new());
    while i > 0 || j > 0 {
        if i > 0 && j > 0 && old[i - 1] == new[j - 1] {
            out.push((' ', old[i - 1].clone()));
            i -= 1;
            j -= 1;
        } else if j > 0 && (i == 0 || dp[i][j - 1] >= dp[i - 1][j]) {
            out.push(('+', new[j - 1].clone()));
            j -= 1;
        } else {
            out.push(('-', old[i - 1].clone()));
            i -= 1;
        }
    }
    out.reverse();
    Some(out)
}

/// Dimensions read directly from the reachable instructions. Pseudocode is
/// derived from the same instructions plus decompiler context (callee names,
/// library signatures), so it can explain a change but never establish one.
const CODE: [&str; 4] = ["instructions", "calls", "strings", "cfg"];

/// Aggregate per-dimension results into one verdict with an explanation.
/// Only a code dimension can make a pair `changed`. Any `unknown` dimension
/// keeps the verdict `unknown`. With every dimension established, raw-byte
/// and pseudocode differences are explained, not counted.
fn pair_verdict(dimensions: &serde_json::Map<String, Value>) -> (&'static str, String) {
    let result = |name: &str| dimensions[name]["result"].as_str().unwrap_or("unknown");
    if let Some(changed) = CODE.iter().find(|d| result(d) == "changed") {
        return ("changed", format!("{changed} changed"));
    }
    let mut differs = Vec::new();
    if result("bytes") == "changed" {
        differs.push(
            "raw bytes differ only at references that normalize to the same targets (relocation)",
        );
    }
    if result("pseudocode") == "changed" {
        differs.push("pseudocode differs although instructions, calls, strings, and CFG are unchanged (decompiler context such as callee names or signatures)");
    }
    let unknown: Vec<String> = DIMENSIONS
        .iter()
        .filter(|d| result(d) == "unknown")
        .map(|d| {
            format!(
                "{d} ({})",
                dimensions[*d]["reason"].as_str().unwrap_or("unknown")
            )
        })
        .collect();
    if !unknown.is_empty() {
        let noted: String = differs.iter().map(|d| format!("{d}; ")).collect();
        return (
            "unknown",
            format!("{noted}not established: {}", unknown.join(", ")),
        );
    }
    if differs.is_empty() {
        ("unchanged", "every dimension unchanged".into())
    } else {
        ("unchanged", differs.join("; "))
    }
}

fn compare_pair(old: &Side, new: &Side, a: &Facts, b: &Facts, compatible: bool) -> Value {
    let mut dimensions = serde_json::Map::new();
    let decoded = a.decoded && b.decoded;
    let complete = a.complete && b.complete;
    let failed = || dimension("unknown", Some("decode_failed"), Value::Null);
    // Bytes are representation-independent; compared even across profiles.
    let bytes = if !decoded {
        failed()
    } else {
        let tokens = |f: &Facts| Tokens {
            exact: f.bytes.iter().map(|b| format!("{b:02x}")).collect(),
            masked: f.bytes.iter().map(|b| format!("{b:02x}")).collect(),
        };
        let (result, reason, mut detail) = compare_tokens(&tokens(a), &tokens(b), complete);
        detail["old_bytes"] = json!(a.bytes.len());
        detail["new_bytes"] = json!(b.bytes.len());
        dimension(result, reason, detail)
    };
    dimensions.insert("bytes".into(), bytes);
    let incompatible = || dimension("unknown", Some("incompatible_profile"), Value::Null);
    let representation = |f: &dyn Fn() -> Value| {
        if !decoded {
            failed()
        } else if !compatible {
            incompatible()
        } else {
            f()
        }
    };
    dimensions.insert(
        "instructions".into(),
        representation(&|| {
            let (r, why, detail) = compare_tokens(&a.instructions, &b.instructions, complete);
            dimension(r, why, detail)
        }),
    );
    dimensions.insert(
        "calls".into(),
        representation(&|| {
            let (r, why, mut detail) = compare_tokens(&a.calls, &b.calls, complete);
            detail["old"] = json!(a.calls.exact);
            detail["new"] = json!(b.calls.exact);
            detail["indirect_calls"] = json!({"old":a.indirect_calls,"new":b.indirect_calls});
            if r == "unchanged" && (a.indirect_calls > 0 || b.indirect_calls > 0) {
                return dimension("unknown", Some("unresolved_indirect_call"), detail);
            }
            dimension(r, why, detail)
        }),
    );
    dimensions.insert(
        "strings".into(),
        representation(&|| match (&a.pseudocode, &b.pseudocode) {
            (Some(_), Some(_)) => {
                let detail = json!({"old":a.strings,"new":b.strings});
                match (a.strings == b.strings, complete) {
                    (true, true) => dimension("unchanged", None, detail),
                    (false, true) => dimension("changed", None, detail),
                    _ => dimension("unknown", Some("incomplete_analysis"), detail),
                }
            }
            _ => dimension("unknown", Some("decompile_failed"), Value::Null),
        }),
    );
    dimensions.insert(
        "cfg".into(),
        representation(&|| {
            if !(a.reachability_complete && b.reachability_complete) {
                return dimension(
                    "unknown",
                    Some("indirect_or_misaligned_branch"),
                    Value::Null,
                );
            }
            let (r, why, mut detail) = compare_tokens(&a.cfg, &b.cfg, complete);
            detail["old_blocks"] = json!(a.cfg.exact.len());
            detail["new_blocks"] = json!(b.cfg.exact.len());
            dimension(r, why, detail)
        }),
    );
    dimensions.insert(
        "pseudocode".into(),
        representation(&|| match (&a.pseudocode, &b.pseudocode) {
            (Some(x), Some(y)) => {
                let (r, why, mut detail) = compare_tokens(x, y, complete);
                if r != "unchanged" && x.exact != y.exact {
                    match line_diff(&x.exact, &y.exact) {
                        Some(diff) => {
                            let lines: Vec<String> = diff
                                .iter()
                                .filter(|(tag, _)| *tag != ' ')
                                .take(MAX_DIFF_LINES)
                                .map(|(tag, line)| format!("{tag} {line}"))
                                .collect();
                            detail["changed_lines"] =
                                json!(diff.iter().filter(|(t, _)| *t != ' ').count());
                            detail["diff"] = json!(lines);
                        }
                        None => detail["diff_omitted"] = json!("lcs_cell_limit"),
                    }
                }
                dimension(r, why, detail)
            }
            _ => dimension("unknown", Some("decompile_failed"), Value::Null),
        }),
    );
    let (verdict, explanation) = pair_verdict(&dimensions);
    let side = |s: &Side, f: &Facts| {
        json!({"name":f.name,"address":format!("0x{:x}",f.address),"body_instructions":f.body_instructions,
            "complete":f.complete,"reachability_complete":f.reachability_complete,"diagnostics":f.diagnostics,
            "file":s.label})
    };
    json!({"old":side(old, a),"new":side(new, b),"verdict":verdict,"explanation":explanation,
        "dimensions":dimensions})
}

/// Cheap body-byte fingerprint for suggesting (never establishing) pairs.
fn body_fingerprint(side: &Side, address: u64) -> Option<String> {
    let mut diagnostics = vec![];
    let instructions = decode_func_raw_with_diagnostics(
        address,
        &side.symbols,
        &side.segs,
        side.data,
        &mut rsleigh_api::Decoder::new(side.arch),
        &mut diagnostics,
    );
    let reach = body(&instructions, address + DECODE_WINDOW);
    if instructions.is_empty() || reach.falls_off_end || !reach.reachability_complete {
        return None;
    }
    let mut bytes = Vec::new();
    for i in reach.indices {
        bytes.extend_from_slice(side.bytes(instructions[i].0, instructions[i].1.len)?);
    }
    Some(compute_sha256(&bytes))
}

/// `OLD:NEW` names a pair; a bare target names the same function on both
/// sides. `::` inside C++ names is not a separator.
fn split_request(request: &str) -> (String, String) {
    let bytes = request.as_bytes();
    let separator = (0..bytes.len()).find(|&i| {
        bytes[i] == b':' && (i == 0 || bytes[i - 1] != b':') && bytes.get(i + 1) != Some(&b':')
    });
    match separator {
        Some(i) if i > 0 && i + 1 < bytes.len() => {
            (request[..i].to_string(), request[i + 1..].to_string())
        }
        _ => (request.to_string(), request.to_string()),
    }
}

fn resolve(side: &Side, target: &str) -> Result<u64, Value> {
    if let Some(hex) = target
        .strip_prefix("0x")
        .or_else(|| target.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16)
            .map_err(|_| json!({"side":side.label,"reason":"invalid_address","candidates":[]}));
    }
    match side.by_name.get(target).map(Vec::as_slice) {
        Some([address]) => Ok(*address),
        Some(many) => Err(json!({"side":side.label,"reason":"ambiguous_name",
            "candidates":many.iter().map(|a| format!("0x{a:x}")).collect::<Vec<_>>()})),
        None => Err(json!({"side":side.label,"reason":"not_found","candidates":[]})),
    }
}

/// Run a comparison and return its result model. Shared by `--compare`
/// (JSON or text) and the legacy `--diff` text mode.
pub(super) fn run_model(
    old_path: &str,
    old_data: &[u8],
    new_path: &str,
    new_data: &[u8],
    requests: Vec<String>,
    limit: usize,
) -> Result<Value, AgentError> {
    let mut old = Side::load("old", old_path, old_data)?;
    let mut new = Side::load("new", new_path, new_data)?;
    let unique = |side: &Side| -> BTreeSet<String> {
        side.by_name
            .iter()
            .filter(|(name, addresses)| addresses.len() == 1 && !is_generic(name))
            .map(|(name, _)| name.clone())
            .collect()
    };
    let shared: BTreeSet<String> = unique(&old).intersection(&unique(&new)).cloned().collect();
    old.shared = shared.clone();
    new.shared = shared;
    let compatible = old.arch == new.arch && old.convention() == new.convention();
    let mut reasons = vec![];
    if old.arch != new.arch {
        reasons.push(format!("architecture {:?} vs {:?}", old.arch, new.arch));
    }
    if old.convention() != new.convention() {
        reasons.push(format!(
            "calling convention {} vs {}",
            old.convention(),
            new.convention()
        ));
    }

    let mut pairs: Vec<(u64, u64, &'static str)> = vec![];
    let mut unresolved = vec![];
    let mut ambiguous = vec![];
    let mut unmatched = vec![];
    let explicit = !requests.is_empty();
    for (a, b) in requests.iter().map(|r| split_request(r)) {
        match (resolve(&old, &a), resolve(&new, &b)) {
            (Ok(x), Ok(y)) => pairs.push((x, y, "explicit")),
            (x, y) => unresolved.push(
                json!({"request":if a == b { a.clone() } else { format!("{a}:{b}") },
                "old":x.err(),"new":y.err()}),
            ),
        }
    }
    if !explicit {
        let names: BTreeSet<&String> = old.by_name.keys().chain(new.by_name.keys()).collect();
        for name in names {
            let a = old.by_name.get(name).map(Vec::as_slice).unwrap_or(&[]);
            let b = new.by_name.get(name).map(Vec::as_slice).unwrap_or(&[]);
            let hex = |v: &[u64]| v.iter().map(|x| format!("0x{x:x}")).collect::<Vec<_>>();
            if is_generic(name) {
                // Address-derived names do not identify a function across builds.
                for (side, addresses, other) in [(&old, a, &new), (&new, b, &old)] {
                    for address in addresses {
                        unmatched.push(json!({"side":side.label,"name":name,"address":format!("0x{address:x}"),
                            "status":"unknown","reason":"address_derived_name","other_inventory_complete":other.inventory_complete}));
                    }
                }
                continue;
            }
            match (a, b) {
                ([x], [y]) => pairs.push((*x, *y, "unique_symbol")),
                ([], _) | (_, []) => {
                    let (side, addresses, other) = if a.is_empty() {
                        (&new, b, &old)
                    } else {
                        (&old, a, &new)
                    };
                    for address in addresses {
                        unmatched.push(json!({"side":side.label,"name":name,"address":format!("0x{address:x}"),
                            "status":if other.inventory_complete { "absent" } else { "unknown" },
                            "reason":if other.inventory_complete { "name_not_in_complete_inventory" } else { "other_inventory_partial" },
                            "other_inventory_complete":other.inventory_complete}));
                    }
                }
                _ => ambiguous
                    .push(json!({"name":name,"old":hex(a),"new":hex(b),"reason":"duplicate_name"})),
            }
        }
    }
    pairs.sort_by_key(|(a, b, _)| (*a, *b));
    pairs.dedup_by_key(|(a, b, _)| (*a, *b));
    let total = pairs.len();
    pairs.truncate(limit);
    for (index, (a, b, _)) in pairs.iter().enumerate() {
        old.pairs.insert(*a, index);
        new.pairs.insert(*b, index);
    }
    let mut results = vec![];
    for (a, b, basis) in &pairs {
        let fa = facts(&old, *a);
        let fb = facts(&new, *b);
        let mut pair = compare_pair(&old, &new, &fa, &fb, compatible);
        pair["match"] = json!(basis);
        results.push(pair);
    }

    // Identical body bytes suggest a correspondence for unmatched functions;
    // a suggestion never becomes a pair.
    let mut suggestions = vec![];
    let candidates = |side: &Side, label: &str| -> Vec<(u64, String, String)> {
        unmatched
            .iter()
            .filter(|u| u["side"] == label)
            .take(MAX_SUGGESTION_CANDIDATES)
            .filter_map(|u| {
                let address =
                    u64::from_str_radix(u["address"].as_str()?.trim_start_matches("0x"), 16)
                        .ok()?;
                Some((
                    address,
                    u["name"].as_str()?.to_string(),
                    body_fingerprint(side, address)?,
                ))
            })
            .collect()
    };
    let (from_old, from_new) = (candidates(&old, "old"), candidates(&new, "new"));
    for (oa, on, of) in &from_old {
        for (na, nn, nf) in &from_new {
            if of == nf {
                suggestions.push(json!({"old":{"name":on,"address":format!("0x{oa:x}")},
                    "new":{"name":nn,"address":format!("0x{na:x}")},
                    "basis":"identical_body_bytes","established":false}));
            }
        }
    }

    let count = |verdict: &str| results.iter().filter(|r| r["verdict"] == verdict).count();
    let unmatched_count = |side: &str, status: Option<&str>| {
        unmatched
            .iter()
            .filter(|u| u["side"] == side && status.is_none_or(|s| u["status"] == s))
            .count()
    };
    let truncated = total > results.len();
    let partial = truncated
        || count("unknown") > 0
        || results
            .iter()
            .any(|r| r["old"]["complete"] == false || r["new"]["complete"] == false)
        || !ambiguous.is_empty()
        || !unresolved.is_empty()
        || unmatched.iter().any(|u| u["status"] == "unknown");
    let status = if partial { "partial" } else { "ok" };
    Ok(json!({
        "schema":SCHEMA, "status":status, "tool_version":env!("CARGO_PKG_VERSION"),
        "old":old.inventory, "new":new.inventory,
        "profile":{"compatible":compatible,"reasons":reasons,
            "representation_sensitive":REPRESENTATION},
        "pairs":results, "unmatched":unmatched, "ambiguous":ambiguous, "unresolved_requests":unresolved,
        "suggestions":suggestions,
        "summary":{"pairs":results.len(),"unchanged":count("unchanged"),"changed":count("changed"),
            "unknown":count("unknown"),"unmatched_old":unmatched_count("old", None),
            "unmatched_new":unmatched_count("new", None),"absent_old":unmatched_count("old", Some("absent")),
            "absent_new":unmatched_count("new", Some("absent")),"ambiguous":ambiguous.len(),
            "unresolved_requests":unresolved.len()},
        "limits":{"pairs_cap":limit,"pairs_total":total,"pairs_truncated":truncated,
            "diff_lines_cap":MAX_DIFF_LINES,"lcs_cells_cap":MAX_LCS_CELLS,"decode_window_bytes":DECODE_WINDOW},
        "trust":agent_trust_json(),
        "scope":"evidence comparison by dimension; not a proof of semantic equivalence",
    }))
}

pub(super) fn run(old_path: &str, old_data: &[u8], args: &[String]) -> Result<u8, AgentError> {
    let new_path = value_arg(args, "--compare")?.expect("validated mode value");
    let new_data = std::fs::read(new_path).map_err(|e| {
        AgentError::new(
            "input_unreadable",
            format!("cannot read comparison binary: {e}"),
        )
    })?;
    let requests = values_arg(args, "--pair")?
        .into_iter()
        .map(str::to_string)
        .collect();
    let limit = number_arg(args, "--limit", DEFAULT_PAIRS)?.min(MAX_PAIRS);
    let model = run_model(old_path, old_data, new_path, &new_data, requests, limit)?;
    let status = model["status"].as_str().unwrap_or("failed").to_string();
    if args.iter().any(|a| a == "--json") || evidence::capturing() {
        emit(&model);
    } else {
        render_text(&model, false);
    }
    Ok(status_exit(&status))
}

/// Text rendering of the same model; `color` keeps legacy `--diff` styling.
pub(super) fn render_text(model: &Value, color: bool) {
    let s = |v: &Value| {
        v.as_str()
            .map(str::to_string)
            .unwrap_or_else(|| v.to_string())
    };
    let paint = |code: &str, text: String| {
        if color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text
        }
    };
    println!(
        "Comparing: {} vs {}",
        s(&model["old"]["file"]["path"]),
        s(&model["new"]["file"]["path"])
    );
    if model["profile"]["compatible"] == false {
        println!(
            "Profiles differ ({}); representation-sensitive dimensions are unknown",
            model["profile"]["reasons"]
        );
    }
    for pair in model["pairs"].as_array().into_iter().flatten() {
        let verdict = s(&pair["verdict"]);
        if verdict == "unchanged" && color {
            continue;
        }
        println!(
            "=== {}: {} ({} -> {}) ===",
            verdict.to_uppercase(),
            s(&pair["old"]["name"]),
            s(&pair["old"]["address"]),
            s(&pair["new"]["address"])
        );
        println!("  {}", s(&pair["explanation"]));
        for name in DIMENSIONS {
            let dimension = &pair["dimensions"][name];
            let reason = dimension["reason"]
                .as_str()
                .map(|r| format!(" ({r})"))
                .unwrap_or_default();
            println!("  {name}: {}{reason}", s(&dimension["result"]));
        }
        for line in pair["dimensions"]["pseudocode"]["detail"]["diff"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let line = s(line);
            match line.chars().next() {
                Some('-') => println!("{}", paint("31", line)),
                Some('+') => println!("{}", paint("32", line)),
                _ => println!("{line}"),
            }
        }
        if !pair["dimensions"]["pseudocode"]["detail"]["diff_omitted"].is_null() {
            println!("  (pseudocode diff omitted: too large)");
        }
        println!();
    }
    for entry in model["unmatched"].as_array().into_iter().flatten() {
        println!(
            "=== UNMATCHED ({}, {}): {} {} — {} ===",
            s(&entry["side"]),
            s(&entry["status"]),
            s(&entry["name"]),
            s(&entry["address"]),
            s(&entry["reason"])
        );
    }
    for entry in model["ambiguous"].as_array().into_iter().flatten() {
        println!(
            "=== AMBIGUOUS: {} old={} new={} ===",
            s(&entry["name"]),
            entry["old"],
            entry["new"]
        );
    }
    for entry in model["unresolved_requests"]
        .as_array()
        .into_iter()
        .flatten()
    {
        println!(
            "=== UNRESOLVED REQUEST: {} old={} new={} ===",
            s(&entry["request"]),
            entry["old"],
            entry["new"]
        );
    }
    for suggestion in model["suggestions"].as_array().into_iter().flatten() {
        println!(
            "Suggested, not established: {} {} <-> {} {} (identical body bytes)",
            s(&suggestion["old"]["name"]),
            s(&suggestion["old"]["address"]),
            s(&suggestion["new"]["name"]),
            s(&suggestion["new"]["address"])
        );
    }
    let summary = &model["summary"];
    println!("--- Summary ---");
    println!("Unchanged: {}", summary["unchanged"]);
    println!("Changed:   {}", summary["changed"]);
    println!("Unknown:   {}", summary["unknown"]);
    println!(
        "Unmatched: old {} (absent {}), new {} (absent {})",
        summary["unmatched_old"],
        summary["absent_old"],
        summary["unmatched_new"],
        summary["absent_new"]
    );
    println!("Ambiguous: {}", summary["ambiguous"]);
    if model["limits"]["pairs_truncated"] == true {
        println!(
            "Compared {} of {} pairs (raise --limit)",
            summary["pairs"], model["limits"]["pairs_total"]
        );
    }
}

/// Legacy `--diff`: same model, colored text, every matched pair.
pub(super) fn legacy(old_path: &str, new_path: &str, functions: &[String]) {
    let read = |path: &str| std::fs::read(path).map_err(|e| format!("Error reading {path}: {e}"));
    let result = read(old_path).and_then(|old| {
        let new = read(new_path)?;
        run_model(
            old_path,
            &old,
            new_path,
            &new,
            functions.to_vec(),
            MAX_PAIRS,
        )
        .map_err(|e| e.message)
    });
    match result {
        Ok(model) => render_text(&model, true),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dims(results: [&str; 6]) -> serde_json::Map<String, Value> {
        DIMENSIONS
            .iter()
            .zip(results)
            .map(|(name, result)| {
                (
                    name.to_string(),
                    dimension(result, Some("why"), Value::Null),
                )
            })
            .collect()
    }

    #[test]
    fn verdicts_never_upgrade_unknown_and_explain_relocation() {
        let u = "unchanged";
        assert_eq!(pair_verdict(&dims([u, u, u, u, u, u])).0, "unchanged");
        let relocated = pair_verdict(&dims(["changed", u, u, u, u, u]));
        assert_eq!(relocated.0, "unchanged");
        assert!(relocated.1.contains("relocation"));
        assert_eq!(
            pair_verdict(&dims(["changed", "unknown", u, u, u, u])).0,
            "unknown"
        );
        assert_eq!(pair_verdict(&dims([u, u, u, u, u, "unknown"])).0, "unknown");
        assert_eq!(pair_verdict(&dims(["unknown", u, u, u, u, u])).0, "unknown");
        assert_eq!(
            pair_verdict(&dims([u, "unknown", "changed", u, u, u])).0,
            "changed"
        );
        // Pseudocode alone never establishes a change.
        let context = pair_verdict(&dims(["changed", u, u, u, u, "changed"]));
        assert_eq!(context.0, "unchanged");
        assert!(context.1.contains("relocation") && context.1.contains("decompiler context"));
        assert_eq!(
            pair_verdict(&dims([u, "unknown", u, u, u, "changed"])).0,
            "unknown"
        );
    }

    #[test]
    fn token_comparison_separates_unmapped_and_incomplete_differences() {
        let t = |exact: &[&str], masked: &[&str]| Tokens {
            exact: exact.iter().map(|s| s.to_string()).collect(),
            masked: masked.iter().map(|s| s.to_string()).collect(),
        };
        let a = t(&["x", "ext:0x1"], &["x", "?"]);
        let b = t(&["x", "ext:0x2"], &["x", "?"]);
        assert_eq!(compare_tokens(&a, &b, true).0, "unknown");
        assert_eq!(compare_tokens(&a, &a, false).0, "unknown");
        assert_eq!(compare_tokens(&a, &a, true).0, "unchanged");
        let c = t(&["y"], &["y"]);
        assert_eq!(
            compare_tokens(&a, &c, false).0,
            "changed",
            "visible prefix differs"
        );
        let longer = t(&["x", "ext:0x1", "z"], &["x", "?", "z"]);
        assert_eq!(
            compare_tokens(&a, &longer, false).0,
            "unknown",
            "difference beyond a truncated side"
        );
        assert_eq!(compare_tokens(&a, &longer, true).0, "changed");
    }

    #[test]
    fn pair_requests_split_on_single_colons_only() {
        assert_eq!(split_request("a:b"), ("a".into(), "b".into()));
        assert_eq!(
            split_request("0x401000:0x402000"),
            ("0x401000".into(), "0x402000".into())
        );
        assert_eq!(
            split_request("Foo::bar"),
            ("Foo::bar".into(), "Foo::bar".into())
        );
        assert_eq!(
            split_request("Foo::bar:Foo::baz"),
            ("Foo::bar".into(), "Foo::baz".into())
        );
        assert_eq!(split_request("helper"), ("helper".into(), "helper".into()));
    }

    #[test]
    fn line_diff_is_bounded() {
        let lines = |n: usize| (0..n).map(|i| i.to_string()).collect::<Vec<_>>();
        assert!(line_diff(&lines(3), &lines(4)).is_some());
        assert!(line_diff(&lines(2_000), &lines(2_000)).is_none());
    }
}
