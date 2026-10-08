#!/usr/bin/env node
/**
 * CLI Runner for Solana Anchor DevSecOps MCP Server
 * Connects the MCP server to standard I/O (stdio) transport for seamless
 * plug-and-play integration with EGC runtime, Cursor, and Claude Code.
 */

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createAnchorMcpServer } from './server.ts';

async function main() {
  const server = createAnchorMcpServer();
  const transport = new StdioServerTransport();

  process.on('SIGINT', async () => {
    await server.close();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    await server.close();
    process.exit(0);
  });

  await server.connect(transport);
}

main().catch((error) => {
  console.error('[MCP Server Error]', error);
  process.exit(1);
});
