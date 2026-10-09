/**
 * Solana Anchor DevSecOps IDE - Express Full-Stack Server
 * Mounts Vite middlewares in development and serves API routes on /api/*
 */

import express from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { executeMcpToolDirect, MCP_TOOLS } from './src/mcp/server.ts';
import { createGitHubPullRequest } from './src/services/githubPrService.ts';
import { buildContractSecurityGraph } from './src/services/graphRAGService.ts';
import { generateOmgBpmnXml } from './src/services/bpmnWorkflowService.ts';
import { SOA_CATALOG } from './src/services/soaCatalogService.ts';
import { runRealRepositoryScan } from './src/services/realRepoScanner.ts';
import { createRealGitHubIssues } from './src/services/githubIssueService.ts';
import { purgeEgcState } from './src/services/egcStateManager.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3000;
const isProduction = process.env.NODE_ENV === 'production';

app.use(express.json({ limit: '10mb' }));

// ============================================================================
// API ROUTES (/api/*)
// ============================================================================

// 1. GitHub CI/CD Pipeline & PR Synchronization (Real GitHub API with Pre-PR Validation)
// Autoria: Marco Antonio Conceicao
app.post('/api/github/sync', async (req, res) => {
  try {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const { token, owner, repoName, branchName, payload } = req.body;
    const targetBranch = (branchName || payload?.targetBranch || `corrigido/remediacao-c44-${timestamp}`).trim();
    const commitFiles = payload?.commit?.files?.map((f: any) => ({
      path: f.path,
      content: f.content,
    }));

    const result = await createGitHubPullRequest({
      token,
      owner,
      repoName,
      branchName: targetBranch,
      baseBranch: payload?.baseBranch,
      title: payload?.pullRequest?.title,
      body: payload?.pullRequest?.body,
      contractCode: payload?.contractCode,
      commitMessage: payload?.commit?.message,
      files: commitFiles,
    });
    return res.json(result);
  } catch (error: any) {
    const msg = error.message || 'Falha ao processar sincronizacao com o GitHub';
    const status = msg.includes('401') ? 401 : msg.includes('404') ? 404 : msg.includes('422') ? 422 : msg.includes('obrigatorio') || msg.includes('obrigatório') ? 400 : 500;
    return res.status(status).json({
      success: false,
      error: msg,
    });
  }
});

// 2. Model Context Protocol (MCP) Manifest & Tool Discovery Endpoint
app.get('/api/mcp/manifest', (_req, res) => {
  res.json({
    name: 'solana-anchor-devsecops-mcp',
    version: '1.0.0',
    description: 'Solana Anchor DevSecOps IDE - EGC MCP Plugin',
    protocolVersion: '2024-11-05',
    tools: MCP_TOOLS,
  });
});

// 3. Model Context Protocol (MCP) Tool Execution Endpoint
app.post('/api/mcp/execute', async (req, res) => {
  try {
    const { tool, arguments: args } = req.body;
    if (!tool) {
      return res.status(400).json({ error: 'Tool name is required' });
    }
    const result = await executeMcpToolDirect(tool, args || {});
    res.json({ success: true, tool, result });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 3. GraphRAG Security Reasoning Endpoint
app.post('/api/graphrag/audit', async (req, res) => {
  try {
    const { sourceCode } = req.body;
    const graphResult = buildContractSecurityGraph(sourceCode || '');
    res.json({ success: true, graph: graphResult });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 4. BPMN 2.0 OMG XML Export Endpoint
app.get('/api/bpmn/xml', (_req, res) => {
  try {
    const xml = generateOmgBpmnXml();
    res.setHeader('Content-Type', 'application/xml');
    res.send(xml);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// 5. Unified SOA Microservices Catalog
app.get('/api/soa/catalog', (_req, res) => {
  res.json({
    success: true,
    totalServices: SOA_CATALOG.length,
    services: SOA_CATALOG,
    systemStatus: 'HEALTHY',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
  });
});

// 6. EGC Physical Files Inspection Endpoint (Zero Mocks)
// Autoria: Marco Antonio Conceicao
app.get('/api/egc/physical-files', (_req, res) => {
  try {
    const candidatePaths = [
      'programs/solana_sandbox_counter/src/lib.rs',
      'programs/solana_sandbox_counter/src/domain.rs',
      'programs/solana_sandbox_counter/Cargo.toml',
      'Cargo.toml',
      'Anchor.toml',
      'client/index.ts',
      'src/contracts/solanaSandboxCounter.ts',
    ];

    const files: Array<{ path: string; content: string }> = [];

    for (const relPath of candidatePaths) {
      const fullPath = path.resolve(__dirname, relPath);
      if (fs.existsSync(fullPath)) {
        const content = fs.readFileSync(fullPath, 'utf-8');
        files.push({ path: relPath, content });
      }
    }

    res.json({ success: true, count: files.length, files });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 7. EGC Deep Repository & AST Scan Endpoint
app.post('/api/egc/scan', (req, res) => {
  try {
    let files = req.body?.files;
    if (!files || !Array.isArray(files) || files.length === 0) {
      const candidatePaths = [
        'programs/solana_sandbox_counter/src/lib.rs',
        'client/index.ts',
        'src/contracts/solanaSandboxCounter.ts',
      ];
      files = [];
      for (const relPath of candidatePaths) {
        const fullPath = path.resolve(__dirname, relPath);
        if (fs.existsSync(fullPath)) {
          files.push({ path: relPath, content: fs.readFileSync(fullPath, 'utf-8') });
        }
      }
    }

    const scanResult = runRealRepositoryScan(files);
    res.json({ success: true, scanResult });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 8. GitHub Real Issues Creation Endpoint
app.post('/api/github/issues', async (req, res) => {
  try {
    const { token, owner, repoName, findings } = req.body;
    const result = await createRealGitHubIssues({
      token,
      owner,
      repoName,
      findings: findings || [],
    });
    res.json(result);
  } catch (error: any) {
    const msg = error.message || 'Falha ao criar issues no GitHub';
    const status = msg.includes('401') ? 401 : msg.includes('404') ? 404 : 400;
    res.status(status).json({ success: false, error: msg });
  }
});

// 9. EGC State Clean & Auto-Purge Endpoint (egc clean)
app.post('/api/egc/clean', (_req, res) => {
  try {
    const result = purgeEgcState();
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================================
// VITE MIDDLEWARES / STATIC ASSETS
// ============================================================================

async function startServer() {
  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Anchor DevSecOps IDE] Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
