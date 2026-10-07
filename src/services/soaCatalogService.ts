/**
 * Unified SOA (Service-Oriented Architecture) Microservices Catalog
 * Registers and monitors all microservices, protocols, and APIs in the ecosystem
 */

export interface SoaServiceEntry {
  id: string;
  name: string;
  category: 'DEVSECOPS' | 'COMPILER' | 'SECURITY' | 'AGENTIC' | 'INFRASTRUCTURE';
  protocol: 'REST' | 'MCP_JSONRPC' | 'BPMN_2_0' | 'SVM_RPC';
  endpoint: string;
  status: 'ONLINE' | 'ACTIVE' | 'STANDBY';
  latencyMs: number;
  description: string;
  capabilities: string[];
}

export const SOA_CATALOG: SoaServiceEntry[] = [
  {
    id: 'soa-ast-auditor',
    name: 'AST Static Security Auditor Service',
    category: 'SECURITY',
    protocol: 'REST',
    endpoint: '/api/ast/audit',
    status: 'ONLINE',
    latencyMs: 14,
    description: 'Motor estático de inspeção de sintaxe e semântica de macros Anchor (Signer, has_one, Rent-Exempt 49B).',
    capabilities: ['Macro parsing', 'Constraint evaluation', '1-click Quick-Fix patches', 'Rent-Exempt memory checks'],
  },
  {
    id: 'soa-svm-fuzzer',
    name: 'Property-Based SVM Fuzzing Engine',
    category: 'SECURITY',
    protocol: 'REST',
    endpoint: '/api/fuzzing/run',
    status: 'ONLINE',
    latencyMs: 38,
    description: 'Motor estocástico de fuzzing com 10.000 vetores avaliando u64::MAX e invariantes críticas do Solana VM.',
    capabilities: ['10K vector generation', 'Boundary math evaluation', 'Signer spoofing detector', 'CU consumption analysis'],
  },
  {
    id: 'soa-graphrag',
    name: 'GraphRAG Cross-Instruction Reasoner',
    category: 'AGENTIC',
    protocol: 'REST',
    endpoint: '/api/graphrag/audit',
    status: 'ONLINE',
    latencyMs: 42,
    description: 'Grafo semântico de conhecimento cross-instruction com análise de caminhos de ataque e mitigação.',
    capabilities: ['Cross-instruction dependency graphs', 'Attack path traversal', 'Gemini AI semantic grounding'],
  },
  {
    id: 'soa-mcp-server',
    name: 'Model Context Protocol (MCP) Server',
    category: 'AGENTIC',
    protocol: 'MCP_JSONRPC',
    endpoint: '/api/mcp/execute',
    status: 'ONLINE',
    latencyMs: 8,
    description: 'Servidor oficial MCP para exposição de ferramentas de auditoria e simulação para agentes inteligentes.',
    capabilities: ['audit_anchor_ast tool', 'run_property_fuzzer tool', 'derive_pda_spec tool', 'query_graphrag_security tool'],
  },
  {
    id: 'soa-bpmn-workflow',
    name: 'BPMN 2.0 Process Orchestrator',
    category: 'DEVSECOPS',
    protocol: 'BPMN_2_0',
    endpoint: '/api/bpmn/export',
    status: 'ONLINE',
    latencyMs: 5,
    description: 'Orquestrador de processos de qualidade e entrega contínua com exportação padrão OMG BPMN 2.0 XML.',
    capabilities: ['Task sequence flow', 'Quality gates', 'OMG XML generation', 'Enterprise workflow export'],
  },
  {
    id: 'soa-github-pipeline',
    name: 'GitHub CI/CD Sync & Fork Pipeline',
    category: 'INFRASTRUCTURE',
    protocol: 'REST',
    endpoint: '/api/github/sync',
    status: 'ONLINE',
    latencyMs: 65,
    description: 'Sincronizador atómico com API REST do GitHub para criação de forks, commits assinados e abertura de PRs.',
    capabilities: ['Repository fork', 'Atomic branch creation', 'Signed commit push', 'Pull Request automation'],
  },
  {
    id: 'soa-svm-client',
    name: 'Solana Sandbox Client & PDA Derivator',
    category: 'COMPILER',
    protocol: 'SVM_RPC',
    endpoint: '/client/index.ts',
    status: 'ONLINE',
    latencyMs: 12,
    description: 'Cliente Web3 para cálculo de PDA determinística, simulação de instruções e checagem de Rent-Exempt.',
    capabilities: ['Deterministic PDA derivation', 'Rent-Exempt lamport verification', 'Checked math execution'],
  },
];
