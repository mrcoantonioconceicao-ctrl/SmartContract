/**
 * Backward-compatible MCP adapter exports.
 */

export {
  EgcExecutionService,
  EgcExecutionService as EgcMcpExecutionAdapter,
} from '../application/egcExecutionAdapter.ts';
export type {
  GenerateContractArgs,
  GenerateContractResult,
} from '../application/egcExecutionAdapter.ts';
