# EGC CLI & MCP Contract v1

## Status and source of truth

The runtime contract is defined in `src/contracts/v1/index.ts`. It owns the command
catalog, strict Zod input/output schemas, JSON Schema generation, error codes, and
the success/error envelopes. The MCP registry and CLI use this module; the static
MCP manifest is regenerated with `npm run egc:sync-manifest`.

The application dispatcher in `src/application/egcCommandService.ts` invokes
existing domain services and validates outputs before returning them. HTTP, MCP,
and CLI are transport adapters; they do not duplicate command business logic.

## Transport interfaces

### HTTP / REST

Both `server.ts` and `api/index.ts` provide:

| Method and path | Purpose | Authentication |
|---|---|---|
| `GET /api/v1/contract` | Return the v1 command catalog and JSON Schemas | Required |
| `POST /api/v1/execute` | Execute a command using the v1 request/response envelope | Required |
| `GET /api/mcp/manifest` | Discover MCP-compatible tools | Required |
| `POST /api/mcp/execute` | Backward-compatible direct tool adapter | Required |

Use `Authorization: Bearer <key>` or `x-api-key: <key>`. The API key remains
server-side (`ADMIN_API_KEY` or `MCP_API_KEY`); production startup fails if neither
is configured. The compatibility MCP endpoint keeps its existing
`{ success, tool, result }` shape. The v1 endpoint returns the versioned envelope.

Example request:

```json
{
  "command": "audit_rust_ast",
  "correlationId": "4f7d8f85-07a1-4f90-bdad-97afaa24e9d8",
  "input": {
    "sourceCode": "..."
  }
}
```

Successful responses contain `contractVersion`, `success`, `command`,
`correlationId`, `timestamp`, and a schema-validated `result`. Errors use the same
trace fields plus `error.code`, `error.message`, and optional validation `issues`.
The HTTP status is `400` for invalid input, `404` for unknown commands, and `500`
for execution/output failures. Authentication rejection remains `403`.

### MCP

The stdio server advertises the same command names and generated input schemas.
Tool calls return the v1 response envelope as JSON text in MCP content. The
programmatic `executeMcpToolDirect` bridge remains available to existing UI and
REST callers and returns the raw domain result.

Stdio runs locally and does not use or disclose the HTTP administrative keys.
Commands that access GitHub accept a PAT in their input; PAT values are not part
of outputs, and errors/results are scrubbed for the supplied token.

### CLI

Existing aliases remain:

```text
npm run egc:cli -- scan | audit
npm run egc:cli -- lint
npm run egc:cli -- clean | purge
npm run egc:cli -- init --plugin
```

Any v1 command can also be run as `npm run egc:cli -- <command>`. Supply input through
`--input-stdin` or `--input-file <path>`; JSON is deliberately not accepted as a
command-line argument, so credentials need not appear in shell history or process
arguments. For example:

```sh
printf '%s' '{"sourceCode":"..."}' | npm run egc:cli -- audit_rust_ast --input-stdin
```

`init --plugin` only prints local setup information; it does not install or alter
editor configuration.
The human-readable aliases also print the generated `correlationId` and
`timestamp`; direct v1 command invocations print the full response envelope.

## Command catalog

All object inputs are strict: unknown fields are rejected. Optional `files` means
an array of `{ "path": string, "content": string }`; at most 200 files are
accepted, paths are limited to 512 characters, and an individual file's content
to 1,000,000 characters. Each command input is additionally capped at 200,000
UTF-16 code units combined, counting string values and object property names
(keys), including nested objects. Both HTTP adapters cap JSON request bodies at
2 MiB.

| Command | Input | Validated output |
|---|---|---|
| `egc_contract_catalog` | `{}` | Version, command input/output JSON Schemas, error codes, measurement descriptions |
| `generate_anchor_contract` | Optional `programName`, `accountName`, `pdaPrefix`, `hasCheckedMath`, `hasSignerCheck`, `includeCloseInstruction` | Generated Rust, account byte sizing, guards detected in emitted source, AST audit preview; rent lamports use the generator formula, not an RPC quote |
| `audit_rust_ast` | Required `sourceCode` (field maximum 200,000 UTF-16 code units; the combined input limit also counts its property key) | Rule counts, findings, account sizing/PDA checks, audit timestamp |
| `create_github_pr` | Required `token`, `owner`, `repoName`; optional `branchName`, `title`, `body`, `contractCode` | PR URL/number, open/manual-merge state; no PAT |
| `audit_anchor_ast` | Same as `audit_rust_ast` | Same audit output; compatibility alias |
| `run_property_fuzzer` | Optional `vectorCount` (1–20,000), math/signer flags | Executed vectors, invariant results, elapsed time, categories and edge cases |
| `derive_pda_spec` | Required valid `authorityPubkey`; optional printable ASCII seed of 1–32 bytes | Locally derived PDA address, canonical bump, seed data and 49-byte allocation; no RPC rent quote |
| `query_graphrag_security` | Required instruction target; optional source code | Existing engine status, paths, source-less community name or source-built community object, graph counts when source-built |
| `scan_repository_ast` | Optional `files` | Scan timestamp, file/line counters, findings, summary and text-based Solana checks |
| `create_github_issues` | Required `token`, `owner`, `repoName`; optional findings | Created issue records, counts, errors and message; no PAT |
| `execute_egc_one_click` | Required `token`, `owner`, `repoName`; optional branch | Scan, issue and PR results, PDF filename, accumulated errors and cleanup status |
| `analyze_contextual_architecture` | Optional `files` | File, graph, DDD invariant and SOA counts plus the service's architecture summary |
| `run_anchor_lint` | Optional `files` | Lint pass/fail, issue counts, inspected files and findings |
| `run_security_lint` | Optional `files` | Active profile, pass/fail, finding counts and equivalent Clippy command |
| `egc_clean_state` | `{}` | Actual cleanup result, timestamp, prior target and cleanup details |
| `record_batch_audit_receipts` | Required auditor public key and 1–5 validated receipt items; optional batch ID | Locally prepared PDA/batch summary. The score average is derived from supplied items. `submitted` is always false: the underlying receipt service accepts a `Keypair` or async keypair provider and can sign/send, but this v1 adapter accepts only `auditorPubkey` and does not pass a signer. |

If `files` is omitted, repository-reading commands use the existing
`/api/egc/physical-files` source when available and otherwise fall back to the
service's bundled file set. Local CLI/MCP stdio should pass `files` explicitly
when the intended scan target is the caller's working tree.

The generated manifest contains the same names/schemas as the runtime catalog.
`audit_anchor_ast` is a public alias; `clean_egc_state` is accepted internally as
a compatibility alias for `egc_clean_state`, but is not advertised as a separate
tool. The CLI's `init` behavior is informational rather than a domain command.

The generated Anchor contract validates `programName`, `accountName`, and
`pdaPrefix` before Rust generation. `includeCloseInstruction` controls whether
both the `close` instruction and its `CloseAccount` context are emitted.

## Error codes

| Code | Meaning |
|---|---|
| `INVALID_INPUT` | Request or command input failed strict schema validation |
| `UNKNOWN_COMMAND` | Command name is not in the v1 registry |
| `UNAUTHENTICATED` | Reserved response code for transports with authentication semantics |
| `FORBIDDEN` | Reserved response code for authenticated but unauthorized callers |
| `NOT_FOUND` | Reserved response code for a missing domain resource |
| `RATE_LIMITED` | Reserved response code for rate-limited transports |
| `EXECUTION_FAILED` | Domain execution failed |
| `INVALID_OUTPUT` | A domain result did not satisfy its declared v1 output schema |

The HTTP administrative middleware currently returns its existing `403` response
before v1 dispatch; the reserved authentication codes are part of the portable
contract and are not substituted for that legacy middleware response.

## Implemented one-click workflow (BPMN)

The generated BPMN is a non-executable process model (`isExecutable="false"`).
Its displayed task status is `NOT_EXECUTED`; it is not a live workflow monitor and
contains no fixed score threshold, vector count, or success claim.

The actual `executeEgcOneClickFlow` order is:

1. **Input and validation** — accept target repository and GitHub PAT, then run
   target-isolation validation. Invalid targets throw before scan or GitHub calls.
2. **Execution** — record the in-memory target, obtain available repository files,
   extract architecture context, and run the real repository scanner.
3. **Issues** — attempt GitHub issue creation. Errors are accumulated, and the
   flow still attempts the PR.
4. **PR and conditional cleanup** — dispatch through the GitHub PR domain service
   with auto-merge disabled. A successful PR triggers EGC state cleanup; a failed
   PR does not.
5. **Evidence** — generate the PDF from scan findings, created issues and the PR
   result. PDF errors are accumulated rather than hidden.
6. **Audit response** — return success/error state, scan counters/findings,
   issue/PR evidence, PDF filename, errors and whether cleanup ran.

The exported BPMN includes shapes and edge geometry for BPMN visualizers. This
sequence is documented from the implemented service, not inferred from the
former diagram's hard-coded `85` score gate or `10,000`-vector label. Scanner
counters are counted from the scanned file set; the scanner's security score and
GraphRAG/DDD values are local static-engine outputs, not independent
certification. The Anchor generator's rent lamport value is a formula-based
estimate, not a live network quote. These outputs are not claims of on-chain
execution. The batch receipt command is explicitly marked not submitted because
the v1 adapter has no signer input, even though the lower-level receipt service
supports a keypair/provider and transaction submission.
