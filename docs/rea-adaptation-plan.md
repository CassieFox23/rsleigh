# Plan: adapt REA's investigation workflows to rsleigh

Date: 2026-10-09. Status: deliverables 1–4 implemented (see
[implementation status](#implementation-status)); the optional MCP/REA
integration remains unstarted.

Reviewed rsleigh at `16d3d0cb73b62fc41713fb6250c6c862fe63e2e4` and
[REA at `bf934d5592e707ba5e7769043de3a430ed8d4923`](https://github.com/morluto/rea/tree/bf934d5592e707ba5e7769043de3a430ed8d4923).
Recommendations below come from their source and documentation, not a runtime
comparison of the two tools.

## Recommendation

Adapt REA's evidence management and investigation interfaces. The best initial
investment is a discoverable capability contract, portable evidence bundles,
and a durable record of unresolved questions. Follow with structured function
comparison. These improve how agents use rsleigh's existing analysis engine.

REA supplies a broad orchestration layer spanning native providers, application
artifacts, and runtime observations. rsleigh supplies its own decoder, P-code,
SSA, and decompiler. Preserve our Rust implementation and standalone operation;
an REA integration can be an optional consumer. See REA's
[provider boundary][rea-provider] and [tool design][rea-design].

## Implementation status

| Deliverable | Implementation | Validation |
|---|---|---|
| 1. Capability catalog and typed contracts | `cli/agent/contracts.rs` (typed operations, flags with kinds/roles, examples, stable error codes) drives dispatch validation, `--help`, and `cli/agent/capabilities.rs` (`--capabilities [--json]`, `--version [--json]`) | `tests/agent_contracts.rs`: examples execute with schema/exit, stable codes, docs drift, raw/WASM and MIPS/RISC-V coverage |
| 2. Portable evidence bundles | `cli/agent/evidence.rs` (`rsleigh.evidence/v1`, canonical projection v1, store), `cli/agent/bundle.rs` (export/verify/import over `index::publish` and the extracted generation reader) | `tests/agent_evidence.rs`: stable IDs warm/cold/moved, round-trip partial records, corrupt/forged/mixed/undeclared rejection, links |
| 3. Questions, unknowns, handoff | `cli/agent/investigation.rs` (revisions, deduplicated boundary issues, evidence-checked answers, next queries, Markdown handoff, bundle attachment) | `tests/agent_investigation.rs`: reopen without binary, stale revisions, unavailable evidence, indirect-call unknown and contradictions survive handoff |
| 4. Structured function comparison | `cli/agent/compare.rs` (`--compare`, legacy `--diff` renderer) | `tests/agent_compare.rs` with [seed variants](../test-harness/fixtures/agent-re/variants.rs): relocation, constant/callee changes, duplicates, renamed, failed, truncated, incompatible profile |
| Validation throughout | `agent_re_eval --workflows` (seven tasks) in CI | [Workflow tasks](agent-re-evaluation.md#workflow-tasks): 7/7, 0 lost references, 0 incorrect upgrades |

Deviations from the proposal: comparison recomputes facts per run instead of
using `--analysis-cache` (whole-window card analysis includes unreachable
padding, which skewed pseudocode); a verification without the source binary
reports `partial` (exit 2) because only integrity was checked; investigation
evidence cites use `--cite` because `--evidence` already selects evidence
capture on other operations.

## What we already have

| REA idea | Current rsleigh implementation | Remaining opportunity |
|---|---|---|
| Bounded function evidence | [Cards](../rsleigh-cli/src/cli/agent/card.rs), independent instruction/operation pagination, partial statuses | Package selected results for portable investigations |
| Reusable analysis | [Cache](../rsleigh-cli/src/cli/agent/cache.rs), build/input identity, immutable generations, integrity checks | Separate portable observation records from internal cached SSA |
| Evidence provenance | Typed P-code, instruction origins, [semantic slices](../rsleigh-cli/src/cli/agent/slice.rs), conservative memory/call boundaries | Link observations and conclusions across commands |
| Confidence and limitations | [Finding records](../rsleigh-decompile/src/finding.rs), architecture warnings, per-function diagnostics | Keep execution status, coverage, and claim strength independently queryable |
| Agent task validation | [18-task evaluation](agent-re-evaluation.md), six native architectures, explicit unresolved answers | Add handoff, comparison, contract-discovery, and contradiction tasks |
| Analysis comparison | [`diff_binaries`](../rsleigh-cli/src/cli.rs) matches names and compares pseudocode lines | Compare identified functions by dimension with explicit ambiguity |

The [previous agent RE roadmap](llm-re-roadmap.md) is already marked complete.
Do not reopen caching, selectors, provenance, or dependency traversal as new
projects. The evaluation's published pass counts belong to its recorded
revisions; they were not rerun for this review.

## Priority and delivery order

Estimates are engineering days for one contributor, including focused tests
and documentation; confirm them when implementation starts.

| Order | Deliverable | Estimate | Dependency |
|---|---|---:|---|
| 1 | Capability catalog and typed agent contracts | 2–3 days | Existing agent modes |
| 2 | Portable evidence bundle and offline verification | 3–5 days | Contract/identity definitions from 1 |
| 3 | Investigation questions, unknowns, and handoff | 2–4 days | Evidence references from 2 |
| 4 | Structured function comparison | 3–5 days | Contracts and evidence records from 1–2 |
| Later | Optional MCP or REA provider integration | Separate spike | Stable public contracts; measured user need |

Ship each deliverable independently. Start evaluation fixtures with the first
deliverable and extend them throughout. The first two deliverables form a useful
release even if the investigation ledger takes longer.

## 1. Make supported operations discoverable

**REA pattern:** a canonical contract describes each tool's inputs, outputs,
examples, and effects. Providers separately report availability and limitations.
Sources: [contract type][rea-contract] and [provider interface][rea-provider].

**Current gap:** agent dispatch maintains mode-specific schemas and allowed
flags in [agent.rs](../rsleigh-cli/src/cli/agent.rs). Output behavior and stage
support live across [output-formats.md](output-formats.md) and
[architectures.md](architectures.md). The current CLI lacks conventional
`--help`/`--version` handling, as documented in [CLI conventions](cli-reference.md).

Implementation:

1. Add a small typed operation catalog for the existing brief, card, index,
   verification, and slice modes. Record schema versions, legal selectors,
   frontend/architecture support, effects, limits, and example requests.
2. Add target-free `--capabilities --json`, `--help`, and `--version` handling
   before binary-path parsing. These are **proposed flags**, not current syntax.
3. Distinguish operation availability from analysis quality. For example,
   MIPS/RISC-V scalar return selection is supported, while ABI argument/helper
   binding is not. Raw/WASM inputs must not inherit native agent support merely
   because another frontend accepts them.
4. Start typed request/result models at the agent boundary; derive or validate
   schema artifacts and documentation against those models. Add stable error
   codes without changing existing payloads incompatibly. Version any breaking
   contract change and document its migration.
5. Preserve agent exit codes `0/2/1` for complete/partial/failed execution. REA
   permits partial observations with exit 0; adopting its convention would
   weaken our existing scripting contract. Legacy modes can migrate separately.

Likely touch points: `rsleigh-cli/src/cli.rs`, `cli/agent.rs`, new
`cli/agent/contracts.rs` and `cli/agent/capabilities.rs`, and the three guides above.

Acceptance: advertised examples execute with their documented schema and exit
status; invalid flag combinations have stable errors; target-free discovery
does not read a binary or build SSA; raw/WASM and unsupported selectors report
their actual coverage. Test all catalog entries for drift.

## 2. Export an investigation's evidence

**REA pattern:** immutable observations carry content-derived IDs, subject and
provider identity, operation/parameters, locations, limitations, and links to
other observations. Bundles retain records and validate their references.
Sources: [evidence model][rea-evidence], [bundle implementation][rea-bundle],
and [saved evidence workflows][rea-cli].

**Current gap:** our index exports four analysis artifacts, and our cache saves
internal analysis snapshots. Neither is a general portable collection of the
cards, slices, findings, and questions used to reach a conclusion.

Implementation:

1. Introduce an additive `rsleigh.evidence/v1` wrapper and
   `rsleigh.evidence-bundle/v1` manifest. Retain existing card/slice/finding
   payloads and their schema versions inside the wrapper.
2. Bind each record to binary SHA-256, architecture/mode/base, actual tool build,
   effective analysis profile and auxiliary-input identities, operation,
   parameters, payload, coverage, and limitations. Preserve raw instruction and
   P-code coordinates already emitted by cards and slices.
3. Specify a canonical semantic projection before computing IDs. Include
   selected ranges and coverage so different pages cannot collide. Exclude
   incidental absolute paths, elapsed time, and cache-hit counters; retain these
   as separate execution metadata. Version the canonicalization rules.
4. Keep execution status, coverage, and evidence interpretation separate.
   Preserve `pattern | heuristic | proved` and its producer/model scope; do not
   translate REA's confidence labels into ours as if they were equivalent.
5. Export selected records with their referenced dependencies. Reuse publication
   and checksum machinery from [index.rs](../rsleigh-cli/src/cli/agent/index.rs),
   extending its artifact model instead of introducing a second persistence
   implementation. Do not copy entire binaries or caches by default.
6. Provide offline verification of schemas, content IDs, dependency references,
   artifact sizes/checksums, and declared coverage. Source binding can be checked
   when the matching binary is supplied. Without it, report that only bundle
   integrity was checked. Importing observations never executes saved commands
   or treats imported SSA as a trusted runtime cache.

Likely new modules: `cli/agent/evidence.rs` and `cli/agent/bundle.rs`, with shared
identity helpers extracted from `cache.rs`. Keep this outside the stable decoder
surface in `rsleigh-api`.

Acceptance: a bundle can move to another directory and retain evidence IDs;
warm/cold runs with identical semantic output have identical IDs; changed input,
build/profile, or evidence changes the relevant ID; malformed, incomplete,
mixed-target, and corrupt bundles cannot verify as complete. Selected partial
pages remain partial after round-trip. Checksums establish consistency, not the
truth or authorship of an analyst's claims.

## 3. Track questions and unresolved evidence across sessions

**REA pattern:** residual unknowns retain supporting and contradicting evidence,
revision history, resolution requirements, and recommended probes. A recorded
analyst decision is distinguishable from proof of an answer. Sources:
[unknown model][rea-unknown] and [mutation evidence][rea-unknown-evidence].

**Current gap:** slices already expose unresolved boundaries, but our
[handoff workflow](agent-workflow.md#llm-reporting-contract) asks the analyst to
save a prose report and related files manually.

Implementation:

1. Add a local investigation document containing the question, target identity,
   evidence IDs, observations, analyst inferences, unresolved items, and next
   queries. Render a Markdown handoff from the same document.
2. Convert selected unresolved slice boundaries into stable, deduplicated issues
   using target/profile, selector, context/origin, and reason code. Let analysts
   add broader questions explicitly; avoid automatically retaining every warning.
3. Support revision-checked updates with supporting and contradicting evidence.
   Preserve prior revisions and explicit dispositions for answered, withdrawn,
   or out-of-scope questions. Withdrawal must not count as a verified answer.
4. Validate evidence references and resolution requirements. A valid record
   means its references and declared requirements check out; it does not mean
   arbitrary natural-language reasoning has been automatically proved.
5. Generate structured next queries from available capabilities, then render
   commands for the caller's shell. Existing brief suggestions in `agent.rs`
   use POSIX quoting and only the first ranked function; reuse that work while
   making follow-ups reflect the actual missing evidence and platform.

Likely new module: `cli/agent/investigation.rs`, built on deliverable 2. No
background service, model dependency, or automatic command execution is needed.

Acceptance: a second process can reopen an investigation and identify its
pending question without repeating discovery; contradictory records survive
export/import; stale revisions are rejected; unavailable evidence cannot close
a question; an unresolved indirect call remains unresolved after handoff.

## 4. Compare function evidence by dimension

**REA pattern:** compare explicitly supplied function evidence across identity,
calls, references, strings/names, CFG, assembly, and pseudocode. Unsupported
normalization or mismatched providers produces an unresolved dimension.
Sources: [comparison orchestration][rea-compare] and
[dimension comparisons][rea-dimensions]. This is evidence comparison, not proof
of semantic equivalence.

**Current gap:** `diff_binaries` builds a name-to-pseudocode map and performs a
line diff. Duplicate names can overwrite entries. Input/parse failures return
an empty map, so comparison needs a stronger distinction between missing
analysis and an actually removed function.

Implementation:

1. Extract comparison logic from `cli.rs` into `cli/agent/compare.rs` with a
   versioned JSON result and the same model driving text output.
2. Start with explicit old/new function addresses and unambiguous symbol pairs.
   Return ambiguous/unmatched candidates for duplicate, stripped, or renamed
   functions. FID or structural similarity may suggest pairs later; it must not
   silently establish correspondence.
3. Compare bytes, calls/imports, strings, CFG, and pseudocode separately using
   existing analysis and caches. Cards do not currently expose every required
   facet; reuse the internal analysis, adding typed facet data where necessary.
   Report `changed`, `unchanged`, or `unknown` for each compared dimension.
4. Normalize local locations only when the mapping is justified. Do not assume
   equal virtual addresses identify the same function across builds. Require
   compatible tool/analysis profiles for representation-sensitive comparisons.
5. Propagate decode failures, incomplete discovery, pagination, and unresolved
   calls. A missing function is not “removed” if the other inventory is partial.
   Bound comparison work before allocating line-diff tables.

Acceptance fixtures: relocated identical function; deliberate changed constant
or callee; duplicate names; stripped/renamed unmatched function; failed input;
truncated function; incompatible build/profile. No failed or incomplete case
may become an unexplained “unchanged” result.

## Optional integration after the core work

REA's [provider interface][rea-provider] is a plausible route for exposing
rsleigh inside REA. A small prototype could map supported listing, function
inspection, disassembly, pseudocode, and reference operations onto versioned
rsleigh output. It must report unsupported operations and preserve partial
analysis, build identity, and limitations. REA's current operation set is
closed: adding a provider and any P-code/slice-specific tools needs upstream
contract work, not just an executable path setting.

Alternatively, a thin rsleigh MCP server could expose the same typed operations.
Extract reusable request handlers from the currently private agent module;
do not duplicate decoding, caching, or evidence semantics in the transport.
Begin with discovery, brief, card, slice, and bundle verification. Adapt REA's
[optional investigation prompts][rea-prompts] only if host evaluations show
they improve task completion. Test CLI/adapter parity for partial results,
invalid inputs, cancellation, and resource cleanup.

Choose one integration after a small end-to-end experiment. Building both now
would add maintenance before we know which interface users need.

## Validation throughout

Adapt REA's [conformance approach][rea-readiness]: exercise whole workflows and
keep unknown, unsupported, truncated, and failed results visible. Reuse our
[evaluation runner](../rsleigh-cli/examples/agent_re_eval.rs),
[agent integration tests](../rsleigh-cli/tests/agent_interface.rs), and
[existing CI](../.github/workflows/ci.yml).

Add tasks for capability-guided selection, portable handoff, unresolved-question
retention, contradiction preservation, corrupt/stale evidence, relocated
function comparison, and intentional version divergence. Keep the existing
18 tasks as regression coverage. A test whose expected answer is “unknown” can
pass while its investigation still correctly records an unresolved question.

Record answer and evidence correctness, commands, returned bytes, cold/warm
time, cache work, and artifact size. Require zero lost references and zero
incorrect upgrades from partial/unknown to complete/proved. Measure any claimed
workflow improvement against the current commands on identical inputs.

During implementation, use the documented release-mode CLI tests and task
runner; run decompiler/oracle suites when shared analysis or semantics change.
No runtime regression suite is needed for this Markdown-only proposal.

## Keep out of the initial scope

- REA's browser, Electron, managed-code, process-capture, and provider-launch
  subsystems: substantial independent products outside this adaptation.
- A universal application graph or automatic reconstruction verifier: first
  establish evidence-linked questions and comparisons with bounded claims.
- Replacing our cache, P-code provenance, or confidence vocabulary wholesale.
- Expanding raw/WASM agent support implicitly through a catalog or adapter.

Implement these patterns in Rust. REA's source carries the [MIT license][rea-license];
if implementation later copies code or substantial text, retain its copyright
and permission notice with the copied material. This proposal copies no code.

[rea-provider]: https://github.com/morluto/rea/blob/bf934d5592e707ba5e7769043de3a430ed8d4923/src/application/AnalysisProvider.ts
[rea-design]: https://github.com/morluto/rea/blob/bf934d5592e707ba5e7769043de3a430ed8d4923/docs/tool-design.md
[rea-contract]: https://github.com/morluto/rea/blob/bf934d5592e707ba5e7769043de3a430ed8d4923/src/contracts/toolContractTypes.ts
[rea-evidence]: https://github.com/morluto/rea/blob/bf934d5592e707ba5e7769043de3a430ed8d4923/src/domain/evidence.ts
[rea-bundle]: https://github.com/morluto/rea/blob/bf934d5592e707ba5e7769043de3a430ed8d4923/src/domain/evidenceBundle.ts
[rea-cli]: https://github.com/morluto/rea/blob/bf934d5592e707ba5e7769043de3a430ed8d4923/docs/cli.md
[rea-unknown]: https://github.com/morluto/rea/blob/bf934d5592e707ba5e7769043de3a430ed8d4923/src/domain/residualUnknown.ts
[rea-unknown-evidence]: https://github.com/morluto/rea/blob/bf934d5592e707ba5e7769043de3a430ed8d4923/src/application/investigation/UnknownEvidence.ts
[rea-compare]: https://github.com/morluto/rea/blob/bf934d5592e707ba5e7769043de3a430ed8d4923/src/domain/functionComparison.ts
[rea-dimensions]: https://github.com/morluto/rea/blob/bf934d5592e707ba5e7769043de3a430ed8d4923/src/domain/functionComparisonDimensions.ts
[rea-prompts]: https://github.com/morluto/rea/blob/bf934d5592e707ba5e7769043de3a430ed8d4923/docs/mcp-prompts.md
[rea-readiness]: https://github.com/morluto/rea/blob/bf934d5592e707ba5e7769043de3a430ed8d4923/docs/reconstruction-readiness.md
[rea-license]: https://github.com/morluto/rea/blob/bf934d5592e707ba5e7769043de3a430ed8d4923/LICENSE
