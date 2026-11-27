import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MCP_TOOLS } from '../src/mcp/server.ts';

const manifest = {
  $schema: 'https://modelcontextprotocol.io/schema/manifest.json',
  name: 'solana-anchor-devsecops-mcp',
  displayName: 'Solana Anchor DevSecOps, AST & GraphRAG MCP Plugin',
  version: '1.0.0',
  contractVersion: 'v1',
  protocolVersion: '2024-11-05',
  description: 'MCP and EGC command catalog generated from the v1 runtime contract.',
  author: {
    name: 'Solana Anchor DevSecOps Core Team',
    maintainers: ['mrcoantonioconceicao', 'Felipe Marzock'],
  },
  runtime: {
    type: 'node',
    entry: 'src/mcp/cli.ts',
    transport: 'stdio',
    isolation: 'local_encrypted_machine_isolation',
  },
  capabilities: {
    tools: true,
    resources: false,
    prompts: false,
  },
  tools: MCP_TOOLS.map(tool => ({
    name: tool.name,
    displayName: tool.name.replaceAll('_', ' '),
    description: tool.description,
    inputSchema: tool.inputSchema,
  })),
};

await writeFile(
  resolve(fileURLToPath(new URL('.', import.meta.url)), '../src/mcp/manifest.json'),
  `${JSON.stringify(manifest, null, 2)}\n`,
);
