/**
 * Model Context Protocol (MCP) Server for Solana Anchor DevSecOps IDE
 * Exposes core AST security, smart contract generation, and manual-only GitHub PR tools to EGC
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { EgcMcpExecutionAdapter } from './adapter.ts';

export interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: string;
    properties: Record<string, any>;
    required?: string[];
  };
}

export const MCP_TOOLS: McpToolDefinition[] = [
  {
    name: 'generate_anchor_contract',
    description: 'Generates secure, production-grade Rust/Anchor smart contract code with audited PDA derivations, checked math, authority guards, and rent-exempt sizing.',
    inputSchema: {
      type: 'object',
      properties: {
        programName: { type: 'string', description: 'Anchor program identifier (e.g. solana_sandbox_counter)' },
        accountName: { type: 'string', description: 'PDA state account struct name (e.g. UserCounter)' },
        pdaPrefix: { type: 'string', description: 'Deterministic seed prefix for PDA derivation (e.g. counter)' },
        hasCheckedMath: { type: 'boolean', description: 'Enforce checked arithmetic' },
        hasSignerCheck: { type: 'boolean', description: 'Enforce Signer and has_one constraint' },
      },
    },
  },
  {
    name: 'audit_rust_ast',
    description: 'Executes static AST security audit on Solana Anchor Rust code to detect missing signers, unconstrained accounts, arithmetic overflows, and rent-exempt issues.',
    inputSchema: {
      type: 'object',
      properties: {
        sourceCode: { type: 'string', description: 'Rust/Anchor smart contract source code' },
      },
      required: ['sourceCode'],
    },
  },
  {
    name: 'create_github_pr',
    description: 'Creates and opens a Pull Request on a remote GitHub repository. Strictly enforces manual-only merge policy (no auto-merge) and requires a valid GitHub PAT.',
    inputSchema: {
      type: 'object',
      properties: {
        token: { type: 'string', description: 'GitHub Personal Access Token (PAT, e.g. ghp_... or github_pat_...)' },
        owner: { type: 'string', description: 'GitHub username or organization' },
        repoName: { type: 'string', description: 'Target repository name' },
        branchName: { type: 'string', description: 'Feature branch name' },
        title: { type: 'string', description: 'Pull Request title' },
        body: { type: 'string', description: 'Pull Request markdown body' },
        contractCode: { type: 'string', description: 'Anchor Rust code to include' },
      },
      required: ['token', 'owner', 'repoName'],
    },
  },
  {
    name: 'audit_anchor_ast',
    description: 'Alias for audit_rust_ast: executes static AST security audit on Solana Anchor Rust code.',
    inputSchema: {
      type: 'object',
      properties: {
        sourceCode: { type: 'string', description: 'Rust/Anchor smart contract source code' },
      },
      required: ['sourceCode'],
    },
  },
  {
    name: 'run_property_fuzzer',
    description: 'Generates and runs up to 20,000 property-based fuzz test vectors verifying Solana SVM invariants.',
    inputSchema: {
      type: 'object',
      properties: {
        vectorCount: { type: 'number', description: 'Number of fuzz vectors to evaluate' },
        hasCheckedMath: { type: 'boolean', description: 'Whether checked arithmetic is enabled' },
        hasSignerCheck: { type: 'boolean', description: 'Whether signer check constraint is enforced' },
      },
    },
  },
  {
    name: 'derive_pda_spec',
    description: 'Calculates deterministic PDA address, canonical bump, and verifies exact 49-byte rent-exempt lamport requirement.',
    inputSchema: {
      type: 'object',
      properties: {
        authorityPubkey: { type: 'string', description: 'Wallet public key of authority' },
        seedPrefix: { type: 'string', description: 'Seed string prefix, default "counter"' },
      },
      required: ['authorityPubkey'],
    },
  },
  {
    name: 'query_graphrag_security',
    description: 'Queries GraphRAG cross-instruction dependency graph for Solana vulnerabilities and attack path reasoning.',
    inputSchema: {
      type: 'object',
      properties: {
        instructionTarget: { type: 'string', description: 'Instruction name (e.g. initialize, increment, close)' },
        sourceCode: { type: 'string', description: 'Optional Rust source code' },
      },
      required: ['instructionTarget'],
    },
  },
];

/**
 * Creates and initializes the Anchor DevSecOps MCP Server
 */
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
    }
  );

  // List available tools
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: MCP_TOOLS,
    };
  });

  // Handle tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const result = await executeMcpToolDirect(name, (args as Record<string, any>) || {});

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  });

  return server;
}

/**
 * Direct programmatic tool invoker for frontend, EGC bus, & REST API bridge
 */
export async function executeMcpToolDirect(toolName: string, args: Record<string, any>) {
  switch (toolName) {
    case 'generate_anchor_contract':
      return EgcMcpExecutionAdapter.generateAnchorContract(args);

    case 'audit_rust_ast':
    case 'audit_anchor_ast':
      return EgcMcpExecutionAdapter.auditRustAst(args.sourceCode || '');

    case 'create_github_pr':
      return EgcMcpExecutionAdapter.createGitHubPr({
        token: args.token,
        owner: args.owner,
        repoName: args.repoName,
        branchName: args.branchName,
        title: args.title,
        body: args.body,
        contractCode: args.contractCode,
      });

    case 'run_property_fuzzer':
      return EgcMcpExecutionAdapter.runPropertyFuzzer(
        args.vectorCount || 10000,
        args.hasCheckedMath !== false,
        args.hasSignerCheck !== false
      );

    case 'derive_pda_spec':
      return EgcMcpExecutionAdapter.derivePdaSpec(args.authorityPubkey, args.seedPrefix || 'counter');

    case 'query_graphrag_security':
      return EgcMcpExecutionAdapter.queryGraphRag(args.instructionTarget || 'increment', args.sourceCode);

    default:
      throw new Error(`Tool "${toolName}" not found in Solana Anchor DevSecOps MCP Server`);
  }
}
