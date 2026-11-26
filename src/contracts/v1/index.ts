import { z } from 'zod';
import { PublicKey } from '@solana/web3.js';
import {
  RUST_ACCOUNT_NAME_PATTERN,
  RUST_MODULE_NAME_PATTERN,
} from '../../utils/rustIdentifiers.ts';

export const EGC_CONTRACT_VERSION = 'v1' as const;
export const MAX_SOURCE_LENGTH = 200_000;
export const MAX_SCAN_FILES = 200;
export const MAX_FILE_LENGTH = 1_000_000;
export const MAX_INPUT_STRING_LENGTH = 200_000;
export const MAX_HTTP_JSON_BODY_BYTES = 2 * 1024 * 1024;

const nonEmptyString = z.string().min(1).regex(/\S/);
const uuidSchema = z.string().uuid();
const solanaPublicKeySchema = z.string().min(32).max(44)
  .regex(/^[1-9A-HJ-NP-Za-km-z]+$/)
  .refine(value => {
    try {
      new PublicKey(value);
      return true;
    } catch {
      return false;
    }
  }, 'Must be a valid Solana public key');
const fileSchema = z.object({
  path: nonEmptyString.max(512),
  content: z.string().max(MAX_FILE_LENGTH),
}).strict();
const filesSchema = z.array(fileSchema).max(MAX_SCAN_FILES).optional();

export function getEgcV1InputStringLength(input: unknown): number {
  let totalStringLength = 0;
  const pending: unknown[] = [input];
  const visited = new WeakSet<object>();
  while (pending.length > 0) {
    const value = pending.pop();
    if (typeof value === 'string') {
      totalStringLength += value.length;
    } else if (Array.isArray(value)) {
      if (visited.has(value)) continue;
      visited.add(value);
      for (const nestedValue of value) pending.push(nestedValue);
    } else if (typeof value === 'object' && value !== null) {
      if (visited.has(value)) continue;
      visited.add(value);
      for (const [key, nestedValue] of Object.entries(value)) {
        totalStringLength += key.length;
        pending.push(nestedValue);
      }
    }
  }
  return totalStringLength;
}

const astFindingSchema = z.object({
  id: z.string(),
  ruleId: z.string(),
  title: z.string(),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'PASS']),
  line: z.number().int().nonnegative(),
  snippet: z.string().optional(),
  description: z.string(),
  recommendation: z.string(),
  autoFixAvailable: z.boolean(),
  fixPatch: z.object({
    search: z.string(),
    replace: z.string(),
    explanation: z.string(),
  }).strict().optional(),
}).strict();

const securityLintOutputSchema = z.object({
  timestamp: z.string().datetime(),
  profileUsed: z.enum(['audit_strict', 'devsecops_balanced', 'permissive_rapid']),
  passed: z.boolean(),
  totalFindings: z.number().int().nonnegative(),
  errorCount: z.number().int().nonnegative(),
  warningCount: z.number().int().nonnegative(),
  findings: z.array(z.object({
    id: z.string(),
    engine: z.enum(['clippy', 'eslint']),
    ruleId: z.string(),
    file: z.string(),
    line: z.number().int().nonnegative(),
    snippet: z.string().optional(),
    severity: z.enum(['error', 'warning']),
    message: z.string(),
    remediation: z.string(),
  }).strict()),
  clippyCommandEquivalent: z.string(),
  summary: z.string(),
}).strict();

const astReportSchema = z.object({
  score: z.number().min(0).max(100),
  status: z.enum(['SECURE', 'WARNING', 'VULNERABLE']),
  totalRulesChecked: z.number().int().nonnegative(),
  passedCount: z.number().int().nonnegative(),
  criticalCount: z.number().int().nonnegative(),
  highCount: z.number().int().nonnegative(),
  mediumCount: z.number().int().nonnegative(),
  lowCount: z.number().int().nonnegative(),
  findings: z.array(astFindingSchema),
  accountSpaceAnalysis: z.object({
    declaredSpace: z.number().int().nonnegative().optional(),
    expectedSpace: z.number().int().nonnegative().optional(),
    isExact: z.boolean(),
    discriminatorPresent: z.boolean(),
  }).strict(),
  pdaAnalysis: z.object({
    seedsFound: z.array(z.string()),
    bumpStorageFound: z.boolean(),
    hasDeterministicDerivation: z.boolean(),
  }).strict(),
  auditTimestamp: z.string().datetime(),
}).strict();

const scanFindingSchema = z.object({
  id: z.string(),
  ruleId: z.string(),
  category: z.enum(['PDA_DERIVATION', 'RENT_EXEMPT_MEMORY', 'ARITHMETIC_OVERFLOW', 'SIGNER_VALIDATION']),
  title: z.string(),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'PASS']),
  file: z.string(),
  line: z.number().int().nonnegative(),
  snippet: z.string().optional(),
  description: z.string(),
  recommendation: z.string(),
  remediationCode: z.string().optional(),
}).strict();

const scanSummarySchema = z.object({
  criticalCount: z.number().int().nonnegative(),
  highCount: z.number().int().nonnegative(),
  mediumCount: z.number().int().nonnegative(),
  lowCount: z.number().int().nonnegative(),
  passedCount: z.number().int().nonnegative(),
  securityScore: z.number().min(0).max(100),
  status: z.enum(['SECURE', 'WARNING', 'VULNERABLE']),
}).strict();

const scanOutputSchema = z.object({
  scanTimestamp: z.string().datetime(),
  scannedFilesCount: z.number().int().nonnegative(),
  scannedLinesCount: z.number().int().nonnegative(),
  filesScanned: z.array(z.string()),
  findings: z.array(scanFindingSchema),
  summary: scanSummarySchema,
  solanaGuarantees: z.object({
    deterministicPdas: z.boolean(),
    rentExemptMemory49B: z.boolean(),
    checkedArithmetic: z.boolean(),
    signerAuthorization: z.boolean(),
  }).strict(),
}).strict();

const lintIssueSchema = z.object({
  ruleId: z.string(),
  ruleName: z.string(),
  severity: z.enum(['error', 'warning', 'info']),
  file: z.string(),
  line: z.number().int().nonnegative(),
  snippet: z.string(),
  message: z.string(),
  remediation: z.string(),
}).strict();

const lintOutputSchema = z.object({
  passed: z.boolean(),
  totalIssues: z.number().int().nonnegative(),
  errorCount: z.number().int().nonnegative(),
  warningCount: z.number().int().nonnegative(),
  filesInspected: z.array(z.string()),
  issues: z.array(lintIssueSchema),
  summary: z.string(),
}).strict();

const invariantSchema = z.object({
  name: z.string(),
  description: z.string(),
  passed: z.boolean(),
  vectorsTested: z.number().int().nonnegative(),
  violations: z.number().int().nonnegative(),
  status: z.enum(['VERIFIED', 'FAILED']),
}).strict();

const fuzzOutputSchema = z.object({
  totalVectors: z.number().int().nonnegative(),
  passedVectors: z.number().int().nonnegative(),
  failedVectors: z.number().int().nonnegative(),
  expectedRevertsHandled: z.number().int().nonnegative(),
  executionTimeMs: z.number().nonnegative(),
  vectorsPerSecond: z.number().nonnegative(),
  invariants: z.array(invariantSchema),
  categoryBreakdown: z.record(z.string(), z.object({
    total: z.number().int().nonnegative(),
    passed: z.number().int().nonnegative(),
    reverts: z.number().int().nonnegative(),
  }).strict()),
  sampleEdgeCases: z.array(z.object({
    id: z.number().int().nonnegative(),
    category: z.string(),
    input: z.string(),
    result: z.string(),
    status: z.enum(['PASSED', 'FAILED']),
  }).strict()),
}).strict();

const githubPrOutputSchema = z.object({
  success: z.boolean(),
  mode: z.literal('live_github_api'),
  prStatus: z.literal('OPEN'),
  manualMergeRequired: z.literal(true),
  autoMergeEnabled: z.literal(false),
  prUrl: z.string().url(),
  prNumber: z.number().int().positive(),
  owner: z.string(),
  repo: z.string(),
  branch: z.string(),
  base: z.string().optional(),
  message: z.string(),
}).strict();

const githubIssueSchema = z.object({
  id: z.number().int().nonnegative(),
  number: z.number().int().positive(),
  title: z.string(),
  htmlUrl: z.string().url(),
  state: z.string(),
  findingId: z.string(),
  severity: z.string(),
}).strict();

const githubIssuesOutputSchema = z.object({
  success: z.boolean(),
  totalCreated: z.number().int().nonnegative(),
  issues: z.array(githubIssueSchema),
  errors: z.array(z.string()),
  message: z.string(),
}).strict();

const graphCommunitySchema = z.object({
  name: z.string(),
  domainContext: z.string(),
  riskIndex: z.number().min(0).max(100),
  nodeIds: z.array(z.string()),
  summary: z.string(),
  keyInvariants: z.array(z.string()),
}).strict();

const graphPathSchema = z.object({
  pathId: z.string(),
  originNodeId: z.string(),
  destinationNodeId: z.string(),
  hopsCount: z.number().int().nonnegative(),
  sequence: z.array(z.object({
    nodeId: z.string(),
    edgeLabel: z.string(),
  }).strict()),
  riskOutcome: z.enum(['SECURE_TRANSITION', 'POTENTIAL_EXPLOIT', 'RENT_RECLAIM']),
  reasoning: z.string(),
}).strict();

const graphMetricsSchema = z.object({
  nodes: z.number().int().nonnegative(),
  edges: z.number().int().nonnegative(),
  communities: z.number().int().nonnegative(),
  attackPaths: z.number().int().nonnegative(),
}).strict();

const graphOutputSchema = z.union([
  z.object({
    targetInstruction: z.string(),
    connectedCommunity: z.union([graphCommunitySchema, z.string()]).nullable(),
    status: z.enum(['CERTIFIED_SECURE', 'ACTION_REQUIRED']),
    securityScore: z.number().min(0).max(100),
    multiHopPaths: z.array(graphPathSchema),
    graphMetrics: graphMetricsSchema.nullable(),
  }).strict(),
  z.object({
    targetInstruction: z.string(),
    connectedCommunity: z.union([graphCommunitySchema, z.string()]).nullable(),
    status: z.enum(['CERTIFIED_SECURE', 'ACTION_REQUIRED']),
    crossInstructionRiskScore: z.number().min(0).max(100),
    multiHopPaths: z.array(graphPathSchema),
    graphMetrics: graphMetricsSchema,
  }).strict(),
]);

const generatedContractOutputSchema = z.object({
  programName: z.string(),
  accountName: z.string(),
  pdaPrefix: z.string(),
  rustSourceCode: z.string(),
  spaceAnalysis: z.object({
    discriminatorBytes: z.number().int().nonnegative(),
    fieldsBytes: z.number().int().nonnegative(),
    totalBytes: z.number().int().nonnegative(),
    rentExemptLamports: z.number().int().nonnegative(),
  }).strict(),
  securityGuards: z.object({
    checkedArithmetic: z.boolean(),
    signerGuards: z.boolean(),
    canonicalBumpStorage: z.boolean(),
    manualMergeOnly: z.boolean(),
  }).strict(),
  auditPreview: astReportSchema,
}).strict();

const pdaOutputSchema = z.object({
  programId: z.string(),
  address: z.string(),
  seeds: z.array(z.string()),
  canonicalBump: z.number().int().min(0).max(255),
  allocatedSpaceBytes: z.number().int().positive(),
  derivationStatus: z.literal('DETERMINISTIC_OFF_CURVE_VERIFIED'),
}).strict();

const oneClickOutputSchema = z.object({
  success: z.boolean(),
  scan: z.object({
    scanTimestamp: z.string().datetime(),
    scannedFilesCount: z.number().int().nonnegative(),
    scannedLinesCount: z.number().int().nonnegative(),
    summary: scanSummarySchema,
    solanaGuarantees: scanOutputSchema.shape.solanaGuarantees,
  }).strict(),
  issues: z.object({
    success: z.boolean(),
    totalCreated: z.number().int().nonnegative(),
    errors: z.array(z.string()),
  }).strict(),
  pullRequest: githubPrOutputSchema.nullable(),
  pdfFilename: z.string(),
  errors: z.array(z.string()),
  statePurged: z.boolean(),
  purgeMessage: z.string().optional(),
}).strict();

const architectureOutputSchema = z.object({
  timestamp: z.string().datetime(),
  filesScanned: z.array(z.string()),
  graph: z.object({
    nodeCount: z.number().int().nonnegative(),
    edgeCount: z.number().int().nonnegative(),
    attackPathCount: z.number().int().nonnegative(),
  }).strict(),
  ddd: z.object({
    boundedContext: z.string(),
    aggregateRoot: z.string(),
    invariantCount: z.number().int().nonnegative(),
    violatedInvariantCount: z.number().int().nonnegative(),
  }).strict(),
  soaServicesCount: z.number().int().nonnegative(),
  architecturalSummary: z.string(),
}).strict();

const cleanOutputSchema = z.object({
  success: z.boolean(),
  message: z.string(),
  purgedAt: z.string().datetime(),
  previousTarget: z.string().nullable(),
  details: z.object({
    memoryCacheCleared: z.boolean(),
    localStateUnlinked: z.boolean(),
    localStorageCleared: z.boolean(),
  }).strict(),
}).strict();

const batchReceiptOutputSchema = z.object({
  success: z.literal(false),
  submitted: z.literal(false),
  submissionStatus: z.literal('NOT_SUBMITTED'),
  batchPda: z.string(),
  batchIdHex: z.string(),
  receiptsCount: z.number().int().nonnegative(),
  totalFindings: z.number().int().nonnegative(),
  averageSecurityScore: z.number().min(0).max(100),
  highestRiskLevel: z.number().int().min(0).max(4),
  rentExemptBytes: z.number().int().nonnegative(),
  timestamp: z.string().datetime(),
  message: z.string(),
}).strict();

const measurementSchema = z.object({
  name: z.string(),
  description: z.string(),
  unit: z.string().optional(),
}).strict();

const jsonSchemaSchema = z.record(z.string(), z.json());
const catalogOutputSchema = z.object({
  contractVersion: z.literal(EGC_CONTRACT_VERSION),
  commands: z.array(z.object({
    name: z.string(),
    description: z.string(),
    inputSchema: jsonSchemaSchema,
    outputSchema: jsonSchemaSchema,
  }).strict()),
  errorCodes: z.array(z.string()),
  limits: z.object({
    maxInputStringLength: z.number().int().positive(),
    maxHttpJsonBodyBytes: z.number().int().positive(),
  }).strict(),
  measurements: z.array(measurementSchema),
}).strict();

const githubFindingSchema = z.object({
  id: z.string(),
  ruleId: z.string(),
  category: z.enum(['PDA_DERIVATION', 'RENT_EXEMPT_MEMORY', 'ARITHMETIC_OVERFLOW', 'SIGNER_VALIDATION']),
  title: z.string(),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'PASS']),
  file: z.string(),
  line: z.number().int().nonnegative(),
  snippet: z.string().optional(),
  description: z.string(),
  recommendation: z.string(),
  remediationCode: z.string().optional(),
}).strict();

const emptyInputSchema = z.object({}).strict();
const commandDefinitions = {
  egc_contract_catalog: {
    description: 'Returns the versioned EGC command catalog and JSON Schemas.',
    inputSchema: emptyInputSchema,
    outputSchema: catalogOutputSchema,
  },
  generate_anchor_contract: {
    description: 'Generates an Anchor contract and returns its source, byte sizing, guards, and AST audit preview.',
    inputSchema: z.object({
      programName: z.string().regex(RUST_MODULE_NAME_PATTERN).optional(),
      accountName: z.string().regex(RUST_ACCOUNT_NAME_PATTERN).optional(),
      pdaPrefix: z.string().regex(/^[A-Za-z0-9_-]{1,32}$/).optional(),
      hasCheckedMath: z.boolean().optional(),
      hasSignerCheck: z.boolean().optional(),
      includeCloseInstruction: z.boolean().optional(),
    }).strict(),
    outputSchema: generatedContractOutputSchema,
  },
  audit_rust_ast: {
    description: 'Audits supplied Rust/Anchor source and reports rule counts, findings, and account/PDA checks.',
    inputSchema: z.object({ sourceCode: z.string().min(1).max(MAX_SOURCE_LENGTH) }).strict(),
    outputSchema: astReportSchema,
  },
  create_github_pr: {
    description: 'Creates a GitHub pull request with manual merge only; the PAT is accepted only as input and is never returned.',
    inputSchema: z.object({
      token: z.string().min(1, 'token é obrigatório').max(4096).regex(/\S/, 'token é obrigatório'),
      owner: z.string().min(1, 'owner é obrigatório').max(100).regex(/\S/, 'owner é obrigatório'),
      repoName: z.string().min(1, 'repoName é obrigatório').max(100).regex(/\S/, 'repoName é obrigatório'),
      branchName: z.string().max(255).optional(),
      title: z.string().max(256).optional(),
      body: z.string().max(50_000).optional(),
      contractCode: z.string().max(MAX_SOURCE_LENGTH).optional(),
    }).strict(),
    outputSchema: githubPrOutputSchema,
  },
  audit_anchor_ast: {
    description: 'Compatibility alias for audit_rust_ast.',
    inputSchema: z.object({ sourceCode: z.string().min(1).max(MAX_SOURCE_LENGTH) }).strict(),
    outputSchema: astReportSchema,
  },
  run_property_fuzzer: {
    description: 'Runs the local property-based model and reports executed vectors, invariant outcomes, and duration.',
    inputSchema: z.object({
      vectorCount: z.number().int().min(1).max(20_000).optional(),
      hasCheckedMath: z.boolean().optional(),
      hasSignerCheck: z.boolean().optional(),
    }).strict(),
    outputSchema: fuzzOutputSchema,
  },
  derive_pda_spec: {
    description: 'Derives the PDA address and canonical bump locally; does not quote an RPC rent balance.',
    inputSchema: z.object({
      authorityPubkey: solanaPublicKeySchema,
      seedPrefix: z.string().regex(/^[\x20-\x7E]{1,32}$/)
        .optional(),
    }).strict(),
    outputSchema: pdaOutputSchema,
  },
  query_graphrag_security: {
    description: 'Returns GraphRAG status, score, community, paths, and graph counts when source is supplied.',
    inputSchema: z.object({
      instructionTarget: nonEmptyString.max(128),
      sourceCode: z.string().max(MAX_SOURCE_LENGTH).optional(),
    }).strict(),
    outputSchema: graphOutputSchema,
  },
  scan_repository_ast: {
    description: 'Scans provided files or the repository and reports measured file/line counts, findings, and Solana guarantees.',
    inputSchema: z.object({ files: filesSchema }).strict(),
    outputSchema: scanOutputSchema,
  },
  create_github_issues: {
    description: 'Creates GitHub issues from supplied scan findings; the PAT is never included in results.',
    inputSchema: z.object({
      token: z.string().min(1, 'token é obrigatório').max(4096).regex(/\S/, 'token é obrigatório'),
      owner: z.string().min(1, 'owner é obrigatório').max(100).regex(/\S/, 'owner é obrigatório'),
      repoName: z.string().min(1, 'repoName é obrigatório').max(100).regex(/\S/, 'repoName é obrigatório'),
      findings: z.array(githubFindingSchema).max(2_000).optional(),
    }).strict(),
    outputSchema: githubIssuesOutputSchema,
  },
  execute_egc_one_click: {
    description: 'Runs the implemented scan, issue creation, PR dispatch, PDF generation, and state cleanup flow.',
    inputSchema: z.object({
      token: z.string().min(1, 'token é obrigatório').max(4096).regex(/\S/, 'token é obrigatório'),
      owner: z.string().min(1, 'owner é obrigatório').max(100).regex(/\S/, 'owner é obrigatório'),
      repoName: z.string().min(1, 'repoName é obrigatório').max(100).regex(/\S/, 'repoName é obrigatório'),
      branchName: z.string().max(255).optional(),
    }).strict(),
    outputSchema: oneClickOutputSchema,
  },
  analyze_contextual_architecture: {
    description: 'Returns measured GraphRAG, DDD invariant, file, and SOA counts for supplied or repository files.',
    inputSchema: z.object({ files: filesSchema }).strict(),
    outputSchema: architectureOutputSchema,
  },
  run_anchor_lint: {
    description: 'Runs the Anchor static linter over supplied or repository files and returns issue counts.',
    inputSchema: z.object({ files: filesSchema }).strict(),
    outputSchema: lintOutputSchema,
  },
  run_security_lint: {
    description: 'Runs the existing Clippy and Web3 security rule model using its active local profile.',
    inputSchema: z.object({ files: filesSchema }).strict(),
    outputSchema: securityLintOutputSchema,
  },
  egc_clean_state: {
    description: 'Purges the local EGC session state and returns the actual cleanup result.',
    inputSchema: emptyInputSchema,
    outputSchema: cleanOutputSchema,
  },
  record_batch_audit_receipts: {
    description: 'Builds a local batch receipt summary. This adapter has no signing-key input and does not submit a Solana transaction.',
    inputSchema: z.object({
      batchId: z.string().min(1).max(128).optional(),
      auditorPubkey: solanaPublicKeySchema,
      items: z.array(z.object({
        targetProgram: solanaPublicKeySchema,
        auditHash: z.string().min(1).max(128),
        riskLevel: z.union([
          z.literal(0),
          z.literal(1),
          z.literal(2),
          z.literal(3),
          z.literal(4),
        ]),
        findingsCount: z.number().int().min(0).max(0xffff_ffff),
        securityScore: z.number().int().min(0).max(100),
      }).strict()).min(1).max(5),
    }).strict(),
    outputSchema: batchReceiptOutputSchema,
  },
} as const;

export const EGC_V1_COMMANDS = commandDefinitions;
export type EgcV1CommandName = keyof typeof EGC_V1_COMMANDS;
export type EgcV1ErrorCode =
  | 'INVALID_INPUT'
  | 'UNKNOWN_COMMAND'
  | 'UNAUTHENTICATED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'RATE_LIMITED'
  | 'EXECUTION_FAILED'
  | 'INVALID_OUTPUT';

export const EGC_V1_ERROR_CODES: EgcV1ErrorCode[] = [
  'INVALID_INPUT',
  'UNKNOWN_COMMAND',
  'UNAUTHENTICATED',
  'FORBIDDEN',
  'NOT_FOUND',
  'RATE_LIMITED',
  'EXECUTION_FAILED',
  'INVALID_OUTPUT',
];

export const EgcV1ExecuteRequestSchema = z.object({
  command: nonEmptyString.max(100),
  input: z.unknown().optional(),
  correlationId: uuidSchema.optional(),
}).strict().superRefine((request, context) => {
  if (getEgcV1InputStringLength(request.input) > MAX_INPUT_STRING_LENGTH) {
    context.addIssue({
      code: 'custom',
      path: ['input'],
      message: `Combined input strings must not exceed ${MAX_INPUT_STRING_LENGTH} characters.`,
    });
  }
});

export const EgcV1ErrorResponseSchema = z.object({
  contractVersion: z.literal(EGC_CONTRACT_VERSION),
  success: z.literal(false),
  command: z.string().optional(),
  correlationId: uuidSchema,
  timestamp: z.string().datetime(),
  error: z.object({
    code: z.enum(EGC_V1_ERROR_CODES),
    message: z.string(),
    issues: z.array(z.object({
      path: z.array(z.union([z.string(), z.number()])),
      code: z.string(),
      message: z.string(),
    }).strict()).optional(),
  }).strict(),
}).strict();

export const EgcV1SuccessEnvelopeSchema = z.object({
  contractVersion: z.literal(EGC_CONTRACT_VERSION),
  success: z.literal(true),
  command: z.string(),
  correlationId: uuidSchema,
  timestamp: z.string().datetime(),
  result: z.json(),
}).strict();

export type EgcV1ErrorResponse = z.infer<typeof EgcV1ErrorResponseSchema>;
export type EgcV1SuccessEnvelope = z.infer<typeof EgcV1SuccessEnvelopeSchema>;
export type EgcV1Response = EgcV1ErrorResponse | EgcV1SuccessEnvelope;

export function getEgcV1SuccessSchema(command: EgcV1CommandName) {
  return z.object({
    contractVersion: z.literal(EGC_CONTRACT_VERSION),
    success: z.literal(true),
    command: z.literal(command),
    correlationId: uuidSchema,
    timestamp: z.string().datetime(),
    result: EGC_V1_COMMANDS[command].outputSchema,
  }).strict();
}

export function toMcpJsonSchema(schema: z.ZodType): {
  type: 'object';
  properties: Record<string, unknown>;
  required?: string[];
  additionalProperties?: boolean;
} {
  const jsonSchema = z.toJSONSchema(schema);
  if (jsonSchema.type !== 'object') {
    throw new Error('MCP tool schemas must describe JSON objects');
  }
  return {
    type: 'object',
    properties: (jsonSchema.properties ?? {}) as Record<string, unknown>,
    ...(jsonSchema.required ? { required: jsonSchema.required } : {}),
    ...(typeof jsonSchema.additionalProperties === 'boolean'
      ? { additionalProperties: jsonSchema.additionalProperties }
      : {}),
  };
}

export function getEgcV1Catalog() {
  return {
    contractVersion: EGC_CONTRACT_VERSION,
    commands: Object.entries(EGC_V1_COMMANDS).map(([name, command]) => ({
      name,
      description: command.description,
      inputSchema: z.toJSONSchema(command.inputSchema),
      outputSchema: z.toJSONSchema(command.outputSchema),
    })),
    errorCodes: [...EGC_V1_ERROR_CODES],
    limits: {
      maxInputStringLength: MAX_INPUT_STRING_LENGTH,
      maxHttpJsonBodyBytes: MAX_HTTP_JSON_BODY_BYTES,
    },
    measurements: [
      { name: 'scannedFilesCount', description: 'Files inspected by the repository scanner.', unit: 'files' },
      { name: 'scannedLinesCount', description: 'Lines counted by the repository scanner.', unit: 'lines' },
      { name: 'securityScore', description: 'Score returned by the existing static analysis service.', unit: '0-100' },
      { name: 'executionTimeMs', description: 'Duration reported by the local fuzz model.', unit: 'ms' },
      { name: 'totalVectors', description: 'Vectors run by the local property-based model.', unit: 'vectors' },
    ],
  };
}

export function createEgcV1ErrorResponse(
  code: EgcV1ErrorCode,
  message: string,
  options: {
    command?: string;
    correlationId?: string;
    issues?: Array<{ path: Array<string | number>; code: string; message: string }>;
  } = {},
): EgcV1ErrorResponse {
  const correlationId = uuidSchema.safeParse(options.correlationId).success
    ? options.correlationId!
    : globalThis.crypto.randomUUID();
  return EgcV1ErrorResponseSchema.parse({
    contractVersion: EGC_CONTRACT_VERSION,
    success: false,
    ...(options.command ? { command: options.command } : {}),
    correlationId,
    timestamp: new Date().toISOString(),
    error: {
      code,
      message,
      ...(options.issues ? { issues: options.issues } : {}),
    },
  });
}
