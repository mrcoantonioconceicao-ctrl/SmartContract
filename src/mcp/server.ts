/**
 * MCP transport adapter for the versioned EGC command contract.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import {
  executeEgcCommandRaw,
  executeEgcContractCommand,
  redactEgcResult,
  safeErrorMessage,
} from '../application/egcCommandService.ts';
import { EGC_V1_COMMANDS, toMcpJsonSchema } from '../contracts/v1/index.ts';

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
    additionalProperties?: boolean;
  };
}

export const MCP_TOOLS: McpToolDefinition[] = Object.entries(EGC_V1_COMMANDS).map(
  ([name, command]) => ({
    name,
    description: command.description,
    inputSchema: toMcpJsonSchema(command.inputSchema),
  }),
);

export function createAnchorMcpServer() {
  const server = new Server(
    {
      name: 'solana-anchor-devsecops-mcp',
      version: '1.0.0',
    },
    {
      capabilities: {
        tools: {},
      },
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: MCP_TOOLS }));

  server.setRequestHandler(CallToolRequestSchema, async request => {
    const { name, arguments: args } = request.params;
    const result = await executeEgcContractCommand(name, args ?? {});
    return {
      isError: !result.success,
      content: [{
        type: 'text',
        text: JSON.stringify(result, null, 2),
      }],
    };
  });

  return server;
}

export async function executeMcpToolDirect(toolName: string, args: Record<string, unknown>) {
  try {
    return redactEgcResult(await executeEgcCommandRaw(toolName, args), args);
  } catch (error) {
    if (error instanceof Error) {
      const message = safeErrorMessage(error, args);
      if (message !== error.message) throw new Error(message, { cause: error });
    }
    throw error;
  }
}
