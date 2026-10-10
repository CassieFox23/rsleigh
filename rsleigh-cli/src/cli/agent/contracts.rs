//! Typed agent operation contracts. Dispatch validation, `--capabilities`,
//! generated usage text, and documentation drift tests all read this catalog,
//! so an accepted flag cannot be missing from discovery output.
use super::*;

/// Value accepted by a flag. Switches take no value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Switch,
    /// Unsigned decimal integer.
    Count,
    /// `0x`-prefixed hexadecimal virtual address.
    Address,
    /// Function name or `0x` address in the current binary.
    Function,
    /// Local filesystem path.
    Path,
    /// Second input binary; evidence identifies it by content, not path.
    Binary,
    /// Free text or an identifier defined by the operation.
    Text,
}

impl Kind {
    fn id(self) -> &'static str {
        match self {
            Kind::Switch => "switch",
            Kind::Count => "count",
            Kind::Address => "address",
            Kind::Function => "function",
            Kind::Path => "path",
            Kind::Binary => "binary",
            Kind::Text => "text",
        }
    }
}

/// How a flag relates to evidence identity. Only semantic parameters enter
/// an evidence record's content ID; the rest are execution metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Role {
    /// Selects or bounds the observation itself (target, selector, page, caps).
    Semantic,
    /// Affects cost or reuse only; any effect on output appears in diagnostics.
    Execution,
    /// Rendering choice; evidence records are always JSON.
    Output,
    /// Evidence capture, storage, and linking.
    Evidence,
}

impl Role {
    fn id(self) -> &'static str {
        match self {
            Role::Semantic => "semantic",
            Role::Execution => "execution",
            Role::Output => "output",
            Role::Evidence => "evidence",
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Flag {
    pub name: &'static str,
    pub kind: Kind,
    pub placeholder: &'static str,
    pub help: &'static str,
    pub repeatable: bool,
    pub role: Role,
}

impl Flag {
    pub fn takes_value(&self) -> bool {
        self.kind != Kind::Switch
    }

    const fn role(self, role: Role) -> Flag {
        Flag { role, ..self }
    }
}

const fn switch(name: &'static str, help: &'static str) -> Flag {
    Flag {
        name,
        kind: Kind::Switch,
        placeholder: "",
        help,
        repeatable: false,
        role: Role::Semantic,
    }
}

const fn value(
    name: &'static str,
    kind: Kind,
    placeholder: &'static str,
    help: &'static str,
) -> Flag {
    Flag {
        name,
        kind,
        placeholder,
        help,
        repeatable: false,
        role: Role::Semantic,
    }
}

const fn repeated(
    name: &'static str,
    kind: Kind,
    placeholder: &'static str,
    help: &'static str,
) -> Flag {
    Flag {
        name,
        kind,
        placeholder,
        help,
        repeatable: true,
        role: Role::Semantic,
    }
}

/// Where the binary path appears relative to the mode flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Target {
    /// `rsleigh FILE --mode ...`
    Binary,
    /// `rsleigh --mode ...`; never reads a target binary.
    None,
    /// Either form; supplying FILE enables source-binding checks.
    OptionalBinary,
}

pub(super) struct Example {
    /// `FILE`, `FUNCTION`, and `DIR` are placeholders for caller values.
    pub argv: &'static [&'static str],
    pub exits: &'static [u8],
    pub description: &'static str,
}

pub(super) struct Operation {
    pub id: &'static str,
    pub mode: Flag,
    pub schema: &'static str,
    pub summary: &'static str,
    pub target: Target,
    pub positional: Option<&'static str>,
    pub flags: &'static [Flag],
    /// (effect, condition under which it occurs)
    pub effects: &'static [(&'static str, &'static str)],
    pub limits: &'static [(&'static str, u64)],
    pub examples: &'static [Example],
}

impl Operation {
    pub fn flag(&self, name: &str) -> Option<&Flag> {
        std::iter::once(&self.mode)
            .chain(self.flags)
            .find(|f| f.name == name)
    }

    /// One usage line generated from the typed contract.
    pub fn usage(&self) -> String {
        let mut line = String::from("rsleigh");
        match self.target {
            Target::Binary => line.push_str(" FILE"),
            Target::OptionalBinary => line.push_str(" [FILE]"),
            Target::None => {}
        }
        if let Some(positional) = self.positional {
            line.push(' ');
            line.push_str(positional);
        }
        line.push(' ');
        line.push_str(&flag_usage(&self.mode));
        for flag in self.flags {
            line.push_str(" [");
            line.push_str(&flag_usage(flag));
            line.push(']');
            if flag.repeatable {
                line.push_str("...");
            }
        }
        line
    }
}

fn flag_usage(flag: &Flag) -> String {
    if flag.takes_value() {
        format!("{} {}", flag.name, flag.placeholder)
    } else {
        flag.name.to_string()
    }
}

const JSON: Flag = switch(
    "--json",
    "Accepted for consistency; this operation always emits JSON",
)
.role(Role::Output);
const CACHE: Flag = value(
    "--analysis-cache",
    Kind::Path,
    "DIR",
    "Reuse verified analysis snapshots; publishes complete snapshots only",
)
.role(Role::Execution);
const MAX_DECODE: Flag = value(
    "--max-decode-instructions",
    Kind::Count,
    "N",
    "Stop decoding after N instructions (partial evidence)",
)
.role(Role::Execution);
const MAX_SSA: Flag = value(
    "--max-ssa-work",
    Kind::Count,
    "N",
    "Stop SSA construction/folding after N work units",
)
.role(Role::Execution);
const DEADLINE: Flag = value(
    "--deadline-ms",
    Kind::Count,
    "N",
    "Cooperative deadline checked between analysis stages",
)
.role(Role::Execution);
const EVIDENCE: Flag = switch(
    "--evidence",
    "Emit an rsleigh.evidence/v1 record wrapping the unchanged payload",
)
.role(Role::Evidence);
const EVIDENCE_STORE: Flag = value(
    "--evidence-store",
    Kind::Path,
    "DIR",
    "Emit the evidence record and persist it as DIR/records/<id>.json",
)
.role(Role::Evidence);
const DERIVED_FROM: Flag = repeated(
    "--derived-from",
    Kind::Text,
    "ID",
    "Link the record to stored evidence it builds on (requires --evidence-store)",
)
.role(Role::Evidence);
const HANDOFF: Flag =
    switch("--handoff", "Render a Markdown handoff instead of JSON").role(Role::Output);
const SHELL: Flag = value(
    "--shell",
    Kind::Text,
    "posix|powershell",
    "Shell for rendered next commands (default: platform)",
)
.role(Role::Output);
const REQUIRE: Flag = repeated(
    "--require",
    Kind::Text,
    "OPERATION",
    "Evidence operation an answer must cite (agent-brief, card, ssa-slice, compare)",
);
const EXIT_COMPLETE: &[u8] = &[0];
const EXIT_EVIDENCE: &[u8] = &[0, 2];

pub(super) const OPERATIONS: &[Operation] = &[
    Operation {
        id: "agent-brief",
        mode: switch("--agent-brief", "Select the agent brief operation"),
        schema: "rsleigh.agent-brief/v1",
        summary: "Bounded ranked function map, findings, file identity, and next commands",
        target: Target::Binary,
        positional: None,
        flags: &[
            value(
                "--limit",
                Kind::Count,
                "N",
                "Functions to return (1-100, default 25)",
            ),
            JSON,
            EVIDENCE,
            EVIDENCE_STORE,
            DERIVED_FROM,
        ],
        effects: &[("reads_binary", "always")],
        limits: &[
            ("functions_default", AGENT_BRIEF_DEFAULT_FUNCTIONS as u64),
            ("functions_cap", AGENT_BRIEF_MAX_FUNCTIONS as u64),
            ("findings_cap", AGENT_BRIEF_MAX_FINDINGS as u64),
            ("strings_per_function", 5),
            ("pseudocode_bytes", 0),
        ],
        examples: &[Example {
            argv: &["FILE", "--agent-brief", "--limit", "5"],
            exits: EXIT_EVIDENCE,
            description: "Rank where to start",
        }],
    },
    Operation {
        id: "card",
        mode: switch("--card", "Select the function card operation"),
        schema: "rsleigh.card/v2",
        summary: "Paginated instructions, raw P-code, and optional capped pseudocode for one function",
        target: Target::Binary,
        positional: Some("FUNCTION"),
        flags: &[
            switch("--json", "Emit rsleigh.card/v2 JSON instead of text").role(Role::Output),
            switch("--pcode", "Include raw P-code operations"),
            switch("--decompile", "Include capped pseudocode (hypothesis)"),
            value(
                "--instruction-cursor",
                Kind::Count,
                "N",
                "First instruction index of the page",
            ),
            value(
                "--operation-cursor",
                Kind::Count,
                "N",
                "First P-code operation index of the page (requires --pcode)",
            ),
            CACHE,
            MAX_DECODE,
            MAX_SSA,
            DEADLINE,
            EVIDENCE,
            EVIDENCE_STORE,
            DERIVED_FROM,
        ],
        effects: &[
            ("reads_binary", "always"),
            ("reads_debug_companions", "FILE.pdb or FILE.dSYM when present"),
            ("reads_cache", "with --analysis-cache"),
            ("writes_cache", "with --analysis-cache and complete analysis"),
        ],
        limits: &[
            ("instructions_per_page", AGENT_CARD_MAX_INSTRUCTIONS as u64),
            ("operations_per_page", AGENT_CARD_MAX_PCODE_OPS as u64),
            ("pseudocode_bytes", AGENT_CARD_MAX_PSEUDOCODE_BYTES as u64),
        ],
        examples: &[
            Example {
                argv: &["FILE", "FUNCTION", "--card", "--json", "--pcode"],
                exits: EXIT_EVIDENCE,
                description: "First page of instructions and raw P-code",
            },
            Example {
                argv: &[
                    "FILE",
                    "FUNCTION",
                    "--card",
                    "--json",
                    "--pcode",
                    "--decompile",
                    "--operation-cursor",
                    "0",
                ],
                exits: EXIT_EVIDENCE,
                description: "Add capped pseudocode as a hypothesis",
            },
            Example {
                argv: &["FILE", "FUNCTION", "--card", "--pcode", "--evidence-store", "STORE"],
                exits: EXIT_EVIDENCE,
                description: "Record the card as content-addressed evidence",
            },
        ],
    },
    Operation {
        id: "index",
        mode: value(
            "--index",
            Kind::Path,
            "DIR",
            "Publish a new index generation into DIR",
        ),
        schema: "rsleigh.index/v2",
        summary: "Reusable functions, direct-call xrefs, imports, and findings artifacts",
        target: Target::Binary,
        positional: None,
        flags: &[
            value(
                "--limit",
                Kind::Count,
                "N",
                "Functions to retain (1-10000, default 10000)",
            ),
            JSON,
        ],
        effects: &[
            ("reads_binary", "always"),
            ("writes_directory", "new immutable generation plus atomic index.json"),
        ],
        limits: &[
            ("functions_cap", AGENT_INDEX_MAX_FUNCTIONS as u64),
            ("findings_cap", AGENT_INDEX_MAX_FINDINGS as u64),
        ],
        examples: &[Example {
            argv: &["FILE", "--index", "DIR", "--limit", "100"],
            exits: EXIT_EVIDENCE,
            description: "Write a reusable map",
        }],
    },
    Operation {
        id: "verify-index",
        mode: value(
            "--verify-index",
            Kind::Path,
            "DIR",
            "Index directory to verify against FILE",
        ),
        schema: "rsleigh.index-verification/v1",
        summary: "Check index binary identity, tool version, generation, and artifact checksums",
        target: Target::Binary,
        positional: None,
        flags: &[JSON],
        effects: &[("reads_binary", "always"), ("reads_directory", "always")],
        limits: &[],
        examples: &[Example {
            argv: &["FILE", "--verify-index", "DIR"],
            exits: EXIT_COMPLETE,
            description: "Verify the index written above",
        }],
    },
    Operation {
        id: "ssa-slice",
        mode: value(
            "--ssa-slice",
            Kind::Function,
            "FUNCTION",
            "Function whose post-fold SSA is queried",
        ),
        schema: "rsleigh.ssa-slice/v3",
        summary: "Bounded backward data dependencies with raw P-code origins and explicit boundaries",
        target: Target::Binary,
        positional: None,
        flags: &[
            value("--var", Kind::Count, "ID", "Root: SSA variable ID"),
            value(
                "--call-site",
                Kind::Address,
                "0xADDRESS",
                "Root: call instruction (with --arg)",
            ),
            value(
                "--arg",
                Kind::Count,
                "INDEX",
                "Zero-based integer argument (with --call-site)",
            ),
            switch("--return", "Root: returned value"),
            value(
                "--at",
                Kind::Address,
                "0xADDRESS",
                "Return instruction (with --return)",
            ),
            value(
                "--condition",
                Kind::Address,
                "0xADDRESS",
                "Root: conditional branch",
            ),
            CACHE,
            MAX_DECODE,
            MAX_SSA,
            DEADLINE,
            value(
                "--max-nodes",
                Kind::Count,
                "N",
                "Dependency node limit (default 64, cap 256)",
            ),
            value(
                "--max-depth",
                Kind::Count,
                "N",
                "Expression depth limit (default 16, cap 32)",
            ),
            value(
                "--max-call-depth",
                Kind::Count,
                "N",
                "Helper call depth (default 2, cap 8)",
            ),
            value(
                "--max-functions",
                Kind::Count,
                "N",
                "Functions admitted to traversal (default 16, cap 32)",
            ),
            value(
                "--max-traversal-work",
                Kind::Count,
                "N",
                "Traversal work units (default 100000, cap 1000000)",
            ),
            JSON,
            EVIDENCE,
            EVIDENCE_STORE,
            DERIVED_FROM,
        ],
        effects: &[
            ("reads_binary", "always"),
            ("reads_cache", "with --analysis-cache"),
            ("writes_cache", "with --analysis-cache and complete snapshots"),
        ],
        limits: &[
            ("max_nodes_default", 64),
            ("max_nodes_cap", rsleigh_decompile::slice::MAX_NODES as u64),
            ("max_depth_default", 16),
            ("max_depth_cap", rsleigh_decompile::slice::MAX_DEPTH as u64),
            ("max_call_depth_default", 2),
            ("max_call_depth_cap", 8),
            ("max_functions_default", 16),
            ("max_functions_cap", 32),
            ("max_traversal_work_default", 100_000),
            ("max_traversal_work_cap", 1_000_000),
            (
                "origins_per_node",
                rsleigh_decompile::provenance::MAX_ORIGINS as u64,
            ),
        ],
        examples: &[
            Example {
                argv: &["FILE", "--ssa-slice", "FUNCTION", "--return"],
                exits: EXIT_EVIDENCE,
                description: "Trace the value returned by a single-return function",
            },
            Example {
                argv: &["FILE", "--ssa-slice", "FUNCTION", "--return", "--evidence-store", "STORE"],
                exits: EXIT_EVIDENCE,
                description: "Record the slice, including unresolved boundaries, as evidence",
            },
        ],
    },
    Operation {
        id: "compare",
        mode: value(
            "--compare",
            Kind::Binary,
            "NEW",
            "Binary to compare against FILE (the old side)",
        ),
        schema: "rsleigh.function-comparison/v1",
        summary: "Compare explicitly paired or uniquely named functions by bytes, instructions, calls, strings, CFG, and pseudocode",
        target: Target::Binary,
        positional: None,
        flags: &[
            repeated(
                "--pair",
                Kind::Text,
                "OLD[:NEW]",
                "Function pair by name or 0x address; default: unique shared symbol names",
            ),
            value(
                "--limit",
                Kind::Count,
                "N",
                "Pairs to compare (default 100, cap 10000)",
            ),
            switch("--json", "Emit rsleigh.function-comparison/v1 JSON instead of text").role(Role::Output),
            EVIDENCE,
            EVIDENCE_STORE,
            DERIVED_FROM,
        ],
        effects: &[
            ("reads_binary", "FILE and NEW"),
            ("reads_debug_companions", "PDB or dSYM next to either input"),
        ],
        limits: &[
            ("pairs_default", 100),
            ("pairs_cap", 10_000),
            ("diff_lines_per_pair", 400),
            ("lcs_cells_per_pair", 2_000_000),
        ],
        examples: &[
            Example {
                argv: &["FILE", "--compare", "FILE", "--json"],
                exits: EXIT_EVIDENCE,
                description: "Compare every uniquely named function",
            },
            Example {
                argv: &["FILE", "--compare", "FILE", "--pair", "FUNCTION", "--json"],
                exits: EXIT_EVIDENCE,
                description: "Compare one explicit pair",
            },
        ],
    },
    Operation {
        id: "export-bundle",
        mode: value(
            "--export-bundle",
            Kind::Path,
            "BUNDLE",
            "Publish a new bundle generation into BUNDLE",
        ),
        schema: "rsleigh.evidence-bundle/v1",
        summary: "Export selected evidence records and their referenced dependencies for one binary",
        target: Target::Binary,
        positional: None,
        flags: &[
            value(
                "--evidence-store",
                Kind::Path,
                "STORE",
                "Store holding the records (required)",
            ),
            repeated(
                "--record",
                Kind::Text,
                "ID",
                "Record to export; default is every record for FILE",
            ),
            value(
                "--investigation",
                Kind::Path,
                "STORE",
                "Also export this investigation, its revisions, and cited evidence",
            ),
            JSON,
        ],
        effects: &[
            ("reads_binary", "always (subject hash only)"),
            ("reads_directory", "the evidence store"),
            ("writes_directory", "new immutable generation plus atomic index.json"),
        ],
        limits: &[],
        examples: &[Example {
            argv: &["FILE", "--export-bundle", "BUNDLE", "--evidence-store", "STORE"],
            exits: EXIT_COMPLETE,
            description: "Package every stored record for FILE",
        }],
    },
    Operation {
        id: "verify-bundle",
        mode: value(
            "--verify-bundle",
            Kind::Path,
            "BUNDLE",
            "Bundle directory to verify offline",
        ),
        schema: "rsleigh.bundle-verification/v1",
        summary: "Verify bundle checksums, content IDs, references, and coverage; FILE adds source binding",
        target: Target::OptionalBinary,
        positional: None,
        flags: &[JSON],
        effects: &[
            ("reads_directory", "the bundle"),
            ("reads_binary", "only when FILE is supplied (hash only)"),
        ],
        limits: &[],
        examples: &[
            Example {
                argv: &["--verify-bundle", "BUNDLE"],
                exits: &[2],
                description: "Integrity only: exits 2 because source binding was not checked",
            },
            Example {
                argv: &["FILE", "--verify-bundle", "BUNDLE"],
                exits: EXIT_COMPLETE,
                description: "Integrity plus source binary identity",
            },
        ],
    },
    Operation {
        id: "import-bundle",
        mode: value(
            "--import-bundle",
            Kind::Path,
            "BUNDLE",
            "Verified bundle to copy into a local store",
        ),
        schema: "rsleigh.bundle-import/v1",
        summary: "Copy verified records into a local evidence store without executing saved commands",
        target: Target::OptionalBinary,
        positional: None,
        flags: &[
            value(
                "--evidence-store",
                Kind::Path,
                "STORE",
                "Destination store for imported records",
            ),
            value(
                "--investigation",
                Kind::Path,
                "STORE",
                "Empty directory to receive the bundled investigation and its records",
            ),
            JSON,
        ],
        effects: &[
            ("reads_directory", "the bundle"),
            ("writes_directory", "STORE/records; existing records are kept"),
        ],
        limits: &[],
        examples: &[Example {
            argv: &["--import-bundle", "BUNDLE", "--evidence-store", "STORE"],
            exits: EXIT_COMPLETE,
            description: "Import into a store; identical records are kept as existing",
        }],
    },
    Operation {
        id: "investigate",
        mode: value(
            "--investigate",
            Kind::Path,
            "STORE",
            "New investigation directory (also its evidence store)",
        ),
        schema: "rsleigh.investigation-view/v1",
        summary: "Start a durable investigation bound to FILE's identity",
        target: Target::Binary,
        positional: None,
        flags: &[
            value("--question", Kind::Text, "TEXT", "The question to answer (required)"),
            REQUIRE,
            HANDOFF,
            SHELL,
            JSON,
        ],
        effects: &[
            ("reads_binary", "always (identity only)"),
            ("writes_directory", "STORE/revisions/000001.json and STORE/investigation.json"),
        ],
        limits: &[],
        examples: &[Example {
            argv: &["FILE", "--investigate", "STORE", "--question", "What does FUNCTION return?"],
            exits: EXIT_COMPLETE,
            description: "Open an investigation whose evidence will live in STORE/records",
        }],
    },
    Operation {
        id: "investigation",
        mode: value(
            "--investigation",
            Kind::Path,
            "STORE",
            "Investigation directory to show or update",
        ),
        schema: "rsleigh.investigation-view/v1",
        summary: "Show an investigation with next queries, render a handoff, or apply one revision-checked update",
        target: Target::OptionalBinary,
        positional: None,
        flags: &[
            HANDOFF,
            SHELL,
            value(
                "--expect-revision",
                Kind::Count,
                "N",
                "Required for updates; rejects a stale revision",
            ),
            value("--add-question", Kind::Text, "TEXT", "Action: add an analyst question"),
            REQUIRE,
            value(
                "--add-unknowns",
                Kind::Text,
                "ID",
                "Action: track unresolved boundaries from a stored slice record",
            ),
            repeated(
                "--node",
                Kind::Count,
                "INDEX",
                "Slice node to track (default: every boundary node)",
            ),
            value("--observe", Kind::Text, "TEXT", "Action: record an observation (needs --cite)"),
            value("--infer", Kind::Text, "TEXT", "Action: record a provisional analyst inference"),
            value("--support", Kind::Text, "ISSUE", "Action: attach supporting evidence"),
            value("--contradict", Kind::Text, "ISSUE", "Action: attach contradicting evidence"),
            value("--resolve", Kind::Text, "ISSUE", "Action: close an issue with --disposition"),
            value(
                "--disposition",
                Kind::Text,
                "answered|withdrawn|out-of-scope",
                "Closing state; only answered checks evidence",
            ),
            value("--note", Kind::Text, "TEXT", "Resolution note"),
            repeated("--cite", Kind::Text, "ID", "Evidence record in STORE/records"),
            JSON,
        ],
        effects: &[
            ("reads_directory", "the investigation and its records"),
            ("reads_binary", "only when FILE is supplied (identity check)"),
            ("writes_directory", "one new immutable revision per update"),
        ],
        limits: &[],
        examples: &[
            Example {
                argv: &["--investigation", "STORE"],
                exits: EXIT_COMPLETE,
                description: "Reopen: pending questions and next queries without rediscovery",
            },
            Example {
                argv: &[
                    "--investigation",
                    "STORE",
                    "--expect-revision",
                    "1",
                    "--add-question",
                    "Which callers supply its input?",
                ],
                exits: EXIT_COMPLETE,
                description: "Revision-checked update",
            },
        ],
    },
];

/// Stable machine-readable failure classes. Messages may change; codes may not.
pub(super) const ERROR_CODES: &[(&str, &str)] = &[
    ("multiple_modes", "More than one operation was selected"),
    (
        "unknown_option",
        "A target-free invocation named no known operation",
    ),
    (
        "unsupported_option",
        "The flag is not part of the selected operation's contract",
    ),
    (
        "unexpected_argument",
        "A positional argument is not accepted here",
    ),
    ("missing_value", "A flag that requires a value has none"),
    (
        "duplicate_option",
        "A non-repeatable flag appears more than once",
    ),
    ("invalid_value", "A flag value has the wrong type or range"),
    (
        "invalid_selector",
        "Slice root flags do not select exactly one root",
    ),
    (
        "invalid_combination",
        "Individually valid flags cannot be combined",
    ),
    (
        "invalid_target",
        "The function target is missing, repeated, or malformed",
    ),
    (
        "target_not_found",
        "No discovered function matches the target",
    ),
    (
        "invalid_cursor",
        "A pagination cursor is beyond the available evidence",
    ),
    (
        "unsupported_input",
        "The input frontend does not implement agent operations",
    ),
    (
        "input_unreadable",
        "The binary or a referenced file cannot be read",
    ),
    (
        "unsupported_format",
        "The container or architecture is not supported",
    ),
    (
        "verification_failed",
        "Stored evidence failed an integrity or identity check",
    ),
    (
        "missing_evidence",
        "Referenced evidence is unavailable in the store or bundle",
    ),
    (
        "stale_revision",
        "The investigation changed since the expected revision",
    ),
    (
        "requirements_unmet",
        "Cited evidence does not satisfy the question's requirements",
    ),
    (
        "write_failed",
        "Publishing output files failed; previous output is unchanged",
    ),
    ("analysis_failed", "Analysis could not produce any evidence"),
    (
        "command_failed",
        "Unclassified failure; inspect the error message",
    ),
];

pub(super) fn find(mode: &str) -> Option<&'static Operation> {
    OPERATIONS.iter().find(|op| op.mode.name == mode)
}

/// A failed agent command. `code` is stable; `message` is for humans.
#[derive(Debug)]
pub(super) struct AgentError {
    pub code: &'static str,
    pub message: String,
}

impl AgentError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        debug_assert!(ERROR_CODES.iter().any(|(c, _)| *c == code), "{code}");
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<String> for AgentError {
    fn from(message: String) -> Self {
        Self::new("command_failed", message)
    }
}

impl From<&str> for AgentError {
    fn from(message: &str) -> Self {
        Self::new("command_failed", message)
    }
}

impl From<AgentError> for String {
    fn from(error: AgentError) -> Self {
        error.message
    }
}

/// Validate argv after the binary (or target-free mode) against `op`.
/// Returns positional arguments. Value checks match the typed flag kinds.
pub(super) fn validate<'a>(
    op: &Operation,
    args: &'a [String],
    start: usize,
) -> Result<Vec<&'a str>, AgentError> {
    let mut positionals = Vec::new();
    let mut i = start;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg.starts_with("--") {
            let flag = op.flag(arg).ok_or_else(|| {
                AgentError::new(
                    "unsupported_option",
                    format!("unsupported {} option: {arg}", op.mode.name),
                )
            })?;
            if flag.takes_value() {
                if flag.repeatable {
                    args.get(i + 1)
                        .filter(|a| !a.starts_with("--"))
                        .ok_or_else(|| {
                            AgentError::new("missing_value", format!("{arg} requires a value"))
                        })?;
                } else {
                    value_arg(args, arg)?;
                }
                i += 1;
            }
        } else if op.positional.is_some() {
            positionals.push(arg);
        } else {
            return Err(AgentError::new(
                "unexpected_argument",
                format!("unexpected argument: {arg}"),
            ));
        }
        i += 1;
    }
    for flag in std::iter::once(&op.mode).chain(op.flags) {
        if flag.kind == Kind::Count && !flag.repeatable && value_arg(args, flag.name)?.is_some() {
            number_arg(args, flag.name, 0)?;
        }
    }
    if op.flag("--limit").is_some()
        && value_arg(args, "--limit")?.is_some()
        && number_arg(args, "--limit", 1)? == 0
    {
        return Err(AgentError::new("invalid_value", "--limit must be positive"));
    }
    Ok(positionals)
}

fn effects_json(op: &Operation) -> Value {
    json!(op
        .effects
        .iter()
        .map(|(effect, condition)| json!({"effect":effect,"condition":condition}))
        .collect::<Vec<_>>())
}

fn flag_json(flag: &Flag) -> Value {
    json!({"name":flag.name,"kind":flag.kind.id(),"role":flag.role.id(),
        "value":flag.takes_value().then_some(flag.placeholder),
        "repeatable":flag.repeatable,"help":flag.help})
}

pub(super) fn operation_json(op: &Operation) -> Value {
    let limits: serde_json::Map<String, Value> = op
        .limits
        .iter()
        .map(|(name, value)| (name.to_string(), json!(value)))
        .collect();
    json!({
        "id":op.id, "mode":flag_json(&op.mode), "schema":op.schema, "summary":op.summary,
        "target":match op.target { Target::Binary=>"binary", Target::None=>"none", Target::OptionalBinary=>"optional_binary" },
        "positional":op.positional, "usage":op.usage(),
        "flags":op.flags.iter().map(flag_json).collect::<Vec<_>>(),
        "effects":effects_json(op), "limits":limits,
        "examples":op.examples.iter().map(|e| json!({"argv":e.argv,"exits":e.exits,"description":e.description})).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_internally_consistent() {
        let mut modes = std::collections::HashSet::new();
        let mut ids = std::collections::HashSet::new();
        for op in OPERATIONS {
            assert!(
                modes.insert(op.mode.name),
                "duplicate mode {}",
                op.mode.name
            );
            assert!(ids.insert(op.id), "duplicate id {}", op.id);
            assert!(op.schema.starts_with("rsleigh.") && op.schema.contains("/v"));
            let mut flags = std::collections::HashSet::from([op.mode.name]);
            for flag in op.flags {
                assert!(
                    flags.insert(flag.name),
                    "{}: duplicate {}",
                    op.id,
                    flag.name
                );
                assert!(flag.name.starts_with("--"));
                assert_eq!(flag.takes_value(), !flag.placeholder.is_empty());
            }
            assert!(!op.examples.is_empty(), "{} needs an example", op.id);
            for example in op.examples {
                let start = usize::from(example.argv[0] == "FILE");
                match op.target {
                    Target::Binary => assert_eq!(start, 1),
                    Target::None => assert_eq!(start, 0),
                    Target::OptionalBinary => {}
                }
                assert!(example.argv.contains(&op.mode.name), "{}", op.id);
                let argv: Vec<String> = std::iter::once("rsleigh")
                    .chain(example.argv.iter().copied())
                    .map(str::to_string)
                    .collect();
                validate(op, &argv, start + 1)
                    .unwrap_or_else(|e| panic!("{} example rejected: {e}", op.id));
            }
        }
    }

    #[test]
    fn validation_reports_stable_codes() {
        let card = find("--card").unwrap();
        let brief = find("--agent-brief").unwrap();
        let argv = |v: &[&str]| -> Vec<String> { v.iter().map(|s| s.to_string()).collect() };
        for (op, args, code) in [
            (
                card,
                argv(&["rsleigh", "f", "x", "--card", "--bogus"]),
                "unsupported_option",
            ),
            (
                brief,
                argv(&["rsleigh", "f", "--agent-brief", "x"]),
                "unexpected_argument",
            ),
            (
                brief,
                argv(&["rsleigh", "f", "--agent-brief", "--limit"]),
                "missing_value",
            ),
            (
                brief,
                argv(&[
                    "rsleigh",
                    "f",
                    "--agent-brief",
                    "--limit",
                    "1",
                    "--limit",
                    "2",
                ]),
                "duplicate_option",
            ),
            (
                brief,
                argv(&["rsleigh", "f", "--agent-brief", "--limit", "oops"]),
                "invalid_value",
            ),
            (
                brief,
                argv(&["rsleigh", "f", "--agent-brief", "--limit", "0"]),
                "invalid_value",
            ),
        ] {
            assert_eq!(validate(op, &args, 2).unwrap_err().code, code, "{args:?}");
        }
    }
}
