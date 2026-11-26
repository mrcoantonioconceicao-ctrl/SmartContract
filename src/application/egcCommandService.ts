import { z } from 'zod';
import { EgcExecutionService } from './egcExecutionAdapter.ts';
import {
  EGC_CONTRACT_VERSION,
  EGC_V1_COMMANDS,
  EgcV1CommandName,
  EgcV1ErrorCode,
  EgcV1Response,
  EgcV1SuccessEnvelopeSchema,
  getEgcV1InputStringLength,
  createEgcV1ErrorResponse,
  getEgcV1Catalog,
  MAX_INPUT_STRING_LENGTH,
} from '../contracts/v1/index.ts';
import { getActiveLintProfile, runSecurityLintAudit } from '../services/securityLintingService.ts';
import { getTargetRepositoryFiles } from '../services/egcCommandCenterService.ts';

type JsonRecord = Record<string, unknown>;

const isRecord = (value: unknown): value is JsonRecord =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

function normalizeCommandName(name: string): string {
  if (name === 'clean_egc_state') return 'egc_clean_state';
  return name;
}

function getCommandName(name: string): EgcV1CommandName | undefined {
  const normalized = normalizeCommandName(name);
  return Object.prototype.hasOwnProperty.call(EGC_V1_COMMANDS, normalized)
    ? normalized as EgcV1CommandName
    : undefined;
}

function getInputSchema(command: EgcV1CommandName) {
  return EGC_V1_COMMANDS[command].inputSchema;
}

export async function executeEgcCommandRaw(
  toolName: string,
  rawInput: unknown,
): Promise<unknown> {
  const command = getCommandName(toolName);
  if (!command) {
    throw new Error(`Unknown EGC command: ${toolName}`);
  }
  if (getEgcV1InputStringLength(rawInput) > MAX_INPUT_STRING_LENGTH) {
    throw new z.ZodError([{
      code: 'custom',
      path: [],
      message: `Combined input strings must not exceed ${MAX_INPUT_STRING_LENGTH} characters.`,
    }]);
  }

  switch (command) {
    case 'egc_contract_catalog':
      EGC_V1_COMMANDS.egc_contract_catalog.inputSchema.parse(rawInput ?? {});
      return getEgcV1Catalog();
    case 'generate_anchor_contract':
      return EgcExecutionService.generateAnchorContract(
        EGC_V1_COMMANDS.generate_anchor_contract.inputSchema.parse(rawInput ?? {}),
      );
    case 'audit_rust_ast':
    case 'audit_anchor_ast':
      return EgcExecutionService.auditRustAst(
        EGC_V1_COMMANDS[command].inputSchema.parse(rawInput ?? {}).sourceCode,
      );
    case 'create_github_pr':
      return EgcExecutionService.createGitHubPr(
        EGC_V1_COMMANDS.create_github_pr.inputSchema.parse(rawInput ?? {}),
      );
    case 'run_property_fuzzer':
      {
        const input = EGC_V1_COMMANDS.run_property_fuzzer.inputSchema.parse(rawInput ?? {});
        return EgcExecutionService.runPropertyFuzzer(
          input.vectorCount ?? 10_000,
          input.hasCheckedMath !== false,
          input.hasSignerCheck !== false,
        );
      }
    case 'derive_pda_spec': {
      const input = EGC_V1_COMMANDS.derive_pda_spec.inputSchema.parse(rawInput ?? {});
      return EgcExecutionService.derivePdaSpec(
        input.authorityPubkey,
        input.seedPrefix ?? 'counter',
      );
    }
    case 'query_graphrag_security': {
      const input = EGC_V1_COMMANDS.query_graphrag_security.inputSchema.parse(rawInput ?? {});
      return EgcExecutionService.queryGraphRag(input.instructionTarget, input.sourceCode);
    }
    case 'scan_repository_ast': {
      const input = EGC_V1_COMMANDS.scan_repository_ast.inputSchema.parse(rawInput ?? {});
      return EgcExecutionService.scanRepositoryAst(input.files);
    }
    case 'create_github_issues': {
      const input = EGC_V1_COMMANDS.create_github_issues.inputSchema.parse(rawInput ?? {});
      return EgcExecutionService.createGitHubIssues(input);
    }
    case 'execute_egc_one_click': {
      const input = EGC_V1_COMMANDS.execute_egc_one_click.inputSchema.parse(rawInput ?? {});
      return EgcExecutionService.executeEgcOneClick(input);
    }
    case 'analyze_contextual_architecture': {
      const input = EGC_V1_COMMANDS.analyze_contextual_architecture.inputSchema.parse(rawInput ?? {});
      return EgcExecutionService.analyzeContextualArchitecture(input.files);
    }
    case 'run_anchor_lint': {
      const input = EGC_V1_COMMANDS.run_anchor_lint.inputSchema.parse(rawInput ?? {});
      return EgcExecutionService.runAnchorLinter(input.files);
    }
    case 'run_security_lint': {
      const input = EGC_V1_COMMANDS.run_security_lint.inputSchema.parse(rawInput ?? {});
      const files = input.files?.length ? input.files : await getTargetRepositoryFiles();
      return runSecurityLintAudit(files, getActiveLintProfile());
    }
    case 'egc_clean_state':
      EGC_V1_COMMANDS.egc_clean_state.inputSchema.parse(rawInput ?? {});
      return EgcExecutionService.cleanEgcState();
    case 'record_batch_audit_receipts': {
      const input = EGC_V1_COMMANDS.record_batch_audit_receipts.inputSchema.parse(rawInput ?? {});
      return EgcExecutionService.recordBatchAuditReceipts(input);
    }
  }
}

function normalizeCommandResult(
  command: EgcV1CommandName,
  value: unknown,
  input: unknown,
): unknown {
  switch (command) {
    case 'egc_contract_catalog':
    case 'generate_anchor_contract':
    case 'audit_rust_ast':
    case 'audit_anchor_ast':
    case 'create_github_pr':
    case 'derive_pda_spec':
    case 'create_github_issues':
    case 'run_anchor_lint':
    case 'run_security_lint':
    case 'egc_clean_state':
    case 'record_batch_audit_receipts':
      return EGC_V1_COMMANDS[command].outputSchema.parse(value);
    case 'run_property_fuzzer': {
      if (!isRecord(value)) throw new Error('Fuzzer result must be an object');
      const { averageComputeUnits: _unmeasuredEstimate, ...measuredResult } = value;
      return EGC_V1_COMMANDS.run_property_fuzzer.outputSchema.parse(measuredResult);
    }
    case 'query_graphrag_security': {
      if (!isRecord(value)) throw new Error('GraphRAG result must be an object');
      if (
        Array.isArray(value.enterpriseNodes) &&
        Array.isArray(value.enterpriseEdges) &&
        Array.isArray(value.communities) &&
        Array.isArray(value.attackPaths) &&
        Array.isArray(value.multiHopPaths) &&
        typeof value.crossInstructionRiskScore === 'number' &&
        typeof value.deterministicAuditStatus === 'string'
      ) {
        const target = isRecord(input) && typeof input.instructionTarget === 'string'
          ? input.instructionTarget
          : '';
        const matchedCommunity = value.communities.find(item =>
          isRecord(item) &&
          Array.isArray(item.nodeIds) &&
          item.nodeIds.some(
            id => typeof id === 'string' && id.toLowerCase().includes(target.toLowerCase()),
          ),
        );
        const connectedCommunity = isRecord(matchedCommunity)
          ? {
              name: matchedCommunity.name,
              domainContext: matchedCommunity.domainContext,
              riskIndex: matchedCommunity.riskIndex,
              nodeIds: matchedCommunity.nodeIds,
              summary: matchedCommunity.summary,
              keyInvariants: matchedCommunity.keyInvariants,
            }
          : null;
        return EGC_V1_COMMANDS.query_graphrag_security.outputSchema.parse({
          targetInstruction: target,
          connectedCommunity,
          status: value.deterministicAuditStatus,
          crossInstructionRiskScore: value.crossInstructionRiskScore,
          multiHopPaths: value.multiHopPaths,
          graphMetrics: {
            nodes: value.enterpriseNodes.length,
            edges: value.enterpriseEdges.length,
            communities: value.communities.length,
            attackPaths: value.attackPaths.length,
          },
        });
      }

      return EGC_V1_COMMANDS.query_graphrag_security.outputSchema.parse({
        targetInstruction: value.targetInstruction,
        connectedCommunity:
          typeof value.connectedCommunity === 'string' ? value.connectedCommunity : null,
        status: value.status,
        securityScore: value.securityScore,
        multiHopPaths: value.multiHopPaths,
        graphMetrics: null,
      });
    }
    case 'scan_repository_ast': {
      if (!isRecord(value)) throw new Error('Repository scan result must be an object');
      const {
        scanTimestamp,
        scannedFilesCount,
        scannedLinesCount,
        filesScanned,
        findings,
        summary,
        solanaGuarantees,
      } = value;
      return EGC_V1_COMMANDS.scan_repository_ast.outputSchema.parse({
        scanTimestamp,
        scannedFilesCount,
        scannedLinesCount,
        filesScanned,
        findings,
        summary,
        solanaGuarantees,
      });
    }
    case 'execute_egc_one_click': {
      if (!isRecord(value) || !isRecord(value.scanResult) || !isRecord(value.issuesResult)) {
        throw new Error('Pipeline result is missing its scan or issue evidence');
      }
      const scan = value.scanResult;
      const issues = value.issuesResult;
      return EGC_V1_COMMANDS.execute_egc_one_click.outputSchema.parse({
        success: value.success,
        scan: {
          scanTimestamp: scan.scanTimestamp,
          scannedFilesCount: scan.scannedFilesCount,
          scannedLinesCount: scan.scannedLinesCount,
          summary: scan.summary,
          solanaGuarantees: scan.solanaGuarantees,
        },
        issues: {
          success: issues.success,
          totalCreated: issues.totalCreated,
          errors: issues.errors,
        },
        pullRequest: value.prResult,
        pdfFilename: value.pdfFilename,
        errors: value.errors,
        statePurged: value.statePurged === true,
        ...(typeof value.purgeMessage === 'string' ? { purgeMessage: value.purgeMessage } : {}),
      });
    }
    case 'analyze_contextual_architecture': {
      if (!isRecord(value) || !isRecord(value.graphRag) || !isRecord(value.dddModel)) {
        throw new Error('Architecture result is missing its GraphRAG or DDD evidence');
      }
      const invariants = Array.isArray(value.dddModel.invariants) ? value.dddModel.invariants : [];
      return EGC_V1_COMMANDS.analyze_contextual_architecture.outputSchema.parse({
        timestamp: value.timestamp,
        filesScanned: value.filesScanned,
        graph: {
          nodeCount: Array.isArray(value.graphRag.nodes) ? value.graphRag.nodes.length : 0,
          edgeCount: Array.isArray(value.graphRag.edges) ? value.graphRag.edges.length : 0,
          attackPathCount: Array.isArray(value.graphRag.attackPaths) ? value.graphRag.attackPaths.length : 0,
        },
        ddd: {
          boundedContext: value.dddModel.boundedContext,
          aggregateRoot: value.dddModel.aggregateRoot,
          invariantCount: invariants.length,
          violatedInvariantCount: invariants.filter(
            item => isRecord(item) && item.status === 'VIOLATED',
          ).length,
        },
        soaServicesCount: Array.isArray(value.soaServices) ? value.soaServices.length : 0,
        architecturalSummary: value.architecturalSummary,
      });
    }
  }
}

function errorCodeFor(error: unknown): EgcV1ErrorCode {
  if (error instanceof z.ZodError) return 'INVALID_INPUT';
  if (error instanceof Error && error.message.startsWith('Unknown EGC command:')) {
    return 'UNKNOWN_COMMAND';
  }
  return 'EXECUTION_FAILED';
}

export function safeErrorMessage(error: unknown, rawInput: unknown): string {
  const message = error instanceof Error ? error.message : 'Command execution failed';
  const token = isRecord(rawInput) && typeof rawInput.token === 'string' ? rawInput.token : '';
  return token ? message.replaceAll(token, '[REDACTED]') : message;
}

export function redactEgcResult(value: unknown, rawInput: unknown): unknown {
  const token = isRecord(rawInput) && typeof rawInput.token === 'string' ? rawInput.token : '';
  if (!token) return value;
  if (typeof value === 'string') return value.replaceAll(token, '[REDACTED]');
  if (Array.isArray(value)) return value.map(item => redactEgcResult(item, rawInput));
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, redactEgcResult(item, rawInput)]),
    );
  }
  return value;
}

export async function executeEgcContractCommand(
  toolName: string,
  rawInput: unknown,
  requestedCorrelationId?: string,
): Promise<EgcV1Response> {
  const correlationId = z.string().uuid().safeParse(requestedCorrelationId).success
    ? requestedCorrelationId!
    : globalThis.crypto.randomUUID();
  const command = getCommandName(toolName);
  if (!command) {
    return createEgcV1ErrorResponse('UNKNOWN_COMMAND', 'Unknown EGC command.', {
      command: toolName,
      correlationId,
    });
  }

  const commandInput = rawInput ?? {};
  if (getEgcV1InputStringLength(commandInput) > MAX_INPUT_STRING_LENGTH) {
    return createEgcV1ErrorResponse('INVALID_INPUT', 'Input exceeds the v1 aggregate string limit.', {
      command,
      correlationId,
      issues: [{
        path: ['input'],
        code: 'custom',
        message: `Combined input strings must not exceed ${MAX_INPUT_STRING_LENGTH} characters.`,
      }],
    });
  }

  const inputResult = getInputSchema(command).safeParse(commandInput);
  if (!inputResult.success) {
    return createEgcV1ErrorResponse('INVALID_INPUT', 'Input does not match the v1 command schema.', {
      command,
      correlationId,
      issues: inputResult.error.issues.map(issue => ({
        path: issue.path.map(part => typeof part === 'number' ? part : String(part)),
        code: issue.code,
        message: issue.message,
      })),
    });
  }

  try {
    const rawResult = await executeEgcCommandRaw(command, inputResult.data);
    let result: unknown;
    try {
      result = redactEgcResult(
        normalizeCommandResult(command, rawResult, inputResult.data),
        rawInput,
      );
    } catch (error) {
      console.error('[EGC contract v1] command returned invalid output', {
        command,
        correlationId,
        message: error instanceof Error ? error.message : 'Output schema validation failed',
      });
      return createEgcV1ErrorResponse(
        'INVALID_OUTPUT',
        'Command result did not match the v1 output schema.',
        { command, correlationId },
      );
    }
    const jsonResult: unknown = JSON.parse(JSON.stringify(result));
    return EgcV1SuccessEnvelopeSchema.parse({
      contractVersion: EGC_CONTRACT_VERSION,
      success: true,
      command,
      correlationId,
      timestamp: new Date().toISOString(),
      result: jsonResult,
    });
  } catch (error) {
    const code = errorCodeFor(error);
    if (code === 'EXECUTION_FAILED') {
      console.error('[EGC contract v1] command execution failed', {
        command,
        correlationId,
        message: safeErrorMessage(error, rawInput),
      });
    }
    return createEgcV1ErrorResponse(
      code,
      code === 'UNKNOWN_COMMAND' ? 'Unknown EGC command.' : safeErrorMessage(error, rawInput),
      { command, correlationId },
    );
  }
}

export function getEgcV1HttpStatus(response: EgcV1Response): number {
  if (response.success) return 200;
  switch (response.error.code) {
    case 'INVALID_INPUT': return 400;
    case 'UNKNOWN_COMMAND':
    case 'NOT_FOUND': return 404;
    case 'UNAUTHENTICATED': return 401;
    case 'FORBIDDEN': return 403;
    case 'RATE_LIMITED': return 429;
    case 'INVALID_OUTPUT':
    case 'EXECUTION_FAILED': return 500;
  }
}
