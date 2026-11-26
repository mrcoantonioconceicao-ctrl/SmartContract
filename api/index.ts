/**
 * Solana Anchor DevSecOps IDE - Vercel Serverless Function Handler
 * Autoria: Marco Antonio Conceicao
 *
 * Exposes API routes on Vercel Serverless runtime without requiring local dev daemon.
 */

import express from 'express';
import { timingSafeEqual } from 'node:crypto';
import fs from 'fs';
import path from 'path';
import { executeMcpToolDirect, MCP_TOOLS } from '../src/mcp/server.ts';
import { createGitHubPullRequest } from '../src/services/githubPrService.ts';
import { buildContractSecurityGraph } from '../src/services/graphRAGService.ts';
import { buildEnterpriseKnowledgeGraph } from '../src/services/graphRAGEnterpriseService.ts';
import { generateOmgBpmnXml } from '../src/services/bpmnWorkflowService.ts';
import { SOA_CATALOG } from '../src/services/soaCatalogService.ts';
import { runRealRepositoryScan } from '../src/services/realRepoScanner.ts';
import { createRealGitHubIssues } from '../src/services/githubIssueService.ts';
import { purgeEgcState } from '../src/services/egcStateManager.ts';
import { getLearningState, recordPrFeedbackEvent } from '../src/services/continuousLearningEngine.ts';
import { processSecurityAgentChat } from '../src/services/securityAgentService.ts';
import {
  EgcV1ExecuteRequestSchema,
  createEgcV1ErrorResponse,
  getEgcV1Catalog,
  MAX_HTTP_JSON_BODY_BYTES,
} from '../src/contracts/v1/index.ts';
import {
  executeEgcContractCommand,
  getEgcV1HttpStatus,
} from '../src/application/egcCommandService.ts';

const app = express();
app.use(express.json({ limit: MAX_HTTP_JSON_BODY_BYTES }));

const ADMIN_KEYS = [process.env.ADMIN_API_KEY, process.env.MCP_API_KEY].filter(
  (key): key is string => typeof key === 'string' && key.length > 0,
);

if (process.env.NODE_ENV === 'production' && ADMIN_KEYS.length === 0) {
  throw new Error('ADMIN_API_KEY or MCP_API_KEY must be configured in production');
}

const requireAdminAuth: express.RequestHandler = (req, res, next) => {
  const authorization = req.get('authorization');
  const token = authorization?.toLowerCase().startsWith('bearer ')
    ? authorization.slice(7).trim()
    : req.get('x-api-key')?.trim();
  const tokenBuffer = token ? Buffer.from(token) : undefined;
  const isValid = ADMIN_KEYS.reduce((valid, key) => {
    const keyBuffer = Buffer.from(key);
    return (
      (tokenBuffer && tokenBuffer.length === keyBuffer.length
        ? timingSafeEqual(tokenBuffer, keyBuffer)
        : false) || valid
    );
  }, false);

  if (!isValid) {
    return res.status(403).json({ success: false, error: 'Acesso administrativo negado.' });
  }

  next();
};

// 1. GitHub CI/CD Pipeline & PR Synchronization
app.post('/api/github/sync', requireAdminAuth, async (req, res) => {
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
    const status = msg.includes('401')
      ? 401
      : msg.includes('404')
      ? 404
      : msg.includes('422')
      ? 422
      : msg.includes('unsupported or invalid')
      ? 400
      : msg.includes('obrigatorio') || msg.includes('obrigatório')
      ? 400
      : 500;
    return res.status(status).json({
      success: false,
      error: msg,
    });
  }
});

// 2. Model Context Protocol (MCP) Manifest & Tool Discovery Endpoint
app.get('/api/mcp/manifest', requireAdminAuth, (_req, res) => {
  res.json({
    name: 'solana-anchor-devsecops-mcp',
    version: '1.0.0',
    description: 'Solana Anchor DevSecOps IDE - EGC MCP Plugin',
    protocolVersion: '2024-11-05',
    tools: MCP_TOOLS,
  });
});

app.get('/api/v1/contract', requireAdminAuth, (_req, res) => {
  res.json(getEgcV1Catalog());
});

app.post('/api/v1/execute', requireAdminAuth, async (req, res) => {
  const parsed = EgcV1ExecuteRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    const response = createEgcV1ErrorResponse(
      'INVALID_INPUT',
      'Request does not match the v1 execution envelope.',
      {
        command: typeof req.body?.command === 'string' ? req.body.command : undefined,
        correlationId: typeof req.body?.correlationId === 'string' ? req.body.correlationId : undefined,
        issues: parsed.error.issues.map(issue => ({
          path: issue.path.map(part => typeof part === 'number' ? part : String(part)),
          code: issue.code,
          message: issue.message,
        })),
      },
    );
    return res.status(400).json(response);
  }

  const response = await executeEgcContractCommand(
    parsed.data.command,
    parsed.data.input,
    parsed.data.correlationId,
  );
  return res.status(getEgcV1HttpStatus(response)).json(response);
});

// 3. Model Context Protocol (MCP) Tool Execution Endpoint
app.post('/api/mcp/execute', requireAdminAuth, async (req, res) => {
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

// 4. GraphRAG Security Reasoning Endpoint
app.post('/api/graphrag/audit', async (req, res) => {
  try {
    const { sourceCode } = req.body;
    const graphResult = buildContractSecurityGraph(sourceCode || '');
    const enterpriseGraph = buildEnterpriseKnowledgeGraph(sourceCode || '');
    res.json({ success: true, graph: graphResult, enterpriseGraph });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 5. BPMN 2.0 OMG XML Export Endpoint
app.get('/api/bpmn/xml', (_req, res) => {
  try {
    const xml = generateOmgBpmnXml();
    res.setHeader('Content-Type', 'application/xml');
    res.send(xml);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// 6. Unified SOA Microservices Catalog
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

// 7. EGC Physical Files Inspection Endpoint (Zero Mocks)
// Autoria: Marco Antonio Conceicao
app.get('/api/egc/physical-files', requireAdminAuth, (_req, res) => {
  try {
    const candidatePaths = [
      'programs/anchor_security_program/src/lib.rs',
      'programs/anchor_security_program/src/domain.rs',
      'programs/anchor_security_program/Cargo.toml',
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
      const fullPath = path.resolve(process.cwd(), relPath);
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

// 8. EGC Deep Repository & AST Scan Endpoint
app.post('/api/egc/scan', requireAdminAuth, (req, res) => {
  try {
    let files = req.body?.files;
    if (!files || !Array.isArray(files) || files.length === 0) {
      const candidatePaths = [
        'programs/anchor_security_program/src/lib.rs',
        'programs/solana_sandbox_counter/src/lib.rs',
        'client/index.ts',
        'src/contracts/solanaSandboxCounter.ts',
      ];
      files = [];
      for (const relPath of candidatePaths) {
        const fullPath = path.resolve(process.cwd(), relPath);
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

// 9. GitHub Real Issues Creation Endpoint
app.post('/api/github/issues', requireAdminAuth, async (req, res) => {
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

// 10. EGC State Clean & Auto-Purge Endpoint (egc clean)
app.post('/api/egc/clean', requireAdminAuth, (_req, res) => {
  try {
    const result = purgeEgcState();
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 11. Continuous Learning & Model Weights Persistence Endpoints
app.get('/api/learning/state', (_req, res) => {
  try {
    const state = getLearningState();
    res.json({ success: true, state });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/learning/feedback', requireAdminAuth, (req, res) => {
  try {
    const { source, ruleId, repository, deltaWeight, explanation } = req.body;
    if (!ruleId) {
      return res.status(400).json({ success: false, error: 'ruleId e obrigatorio' });
    }
    const updatedState = recordPrFeedbackEvent({
      source: source || 'MANUAL_FEEDBACK',
      ruleId,
      repository: repository || 'LocalDevSecOpsWorkspace',
      deltaWeight: typeof deltaWeight === 'number' ? deltaWeight : 2,
      explanation: explanation || 'Correcao de seguranca validada pelo desenvolvedor',
    });
    res.json({ success: true, updatedState });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 12. Security Agent Chat Endpoint (MCP Server & GraphRAG/AST Context)
app.post('/api/security-agent/chat', async (req, res) => {
  try {
    const { message, history, context } = req.body;
    if (!message || typeof message !== 'string') {
      return res.status(400).json({ success: false, error: 'Mensagem e obrigatoria.' });
    }

    const result = await processSecurityAgentChat(
      message,
      Array.isArray(history) ? history : [],
      context || {}
    );

    res.json({
      success: true,
      ...result,
      timestamp: new Date().toISOString(),
    });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message || 'Erro no agente de seguranca' });
  }
});

export default app;
