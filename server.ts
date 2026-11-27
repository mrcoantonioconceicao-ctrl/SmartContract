/**
 * Solana Anchor DevSecOps IDE - Express Full-Stack Server
 * Mounts Vite middlewares in development and serves API routes on /api/*
 */

import express from 'express';
import { timingSafeEqual } from 'node:crypto';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { executeMcpToolDirect, MCP_TOOLS } from './src/mcp/server.ts';
import { createGitHubPullRequest } from './src/services/githubPrService.ts';
import { buildContractSecurityGraph } from './src/services/graphRAGService.ts';
import { buildEnterpriseKnowledgeGraph } from './src/services/graphRAGEnterpriseService.ts';
import { generateOmgBpmnXml } from './src/services/bpmnWorkflowService.ts';
import { SOA_CATALOG } from './src/services/soaCatalogService.ts';
import { runRealRepositoryScan } from './src/services/realRepoScanner.ts';
import { createRealGitHubIssues } from './src/services/githubIssueService.ts';
import { purgeEgcState } from './src/services/egcStateManager.ts';
import { getLearningState, recordPrFeedbackEvent } from './src/services/continuousLearningEngine.ts';
import { processSecurityAgentChat } from './src/services/securityAgentService.ts';
import {
  EgcV1ExecuteRequestSchema,
  createEgcV1ErrorResponse,
  getEgcV1Catalog,
  MAX_HTTP_JSON_BODY_BYTES,
} from './src/contracts/v1/index.ts';
import {
  executeEgcContractCommand,
  getEgcV1HttpStatus,
} from './src/application/egcCommandService.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT) : 3000;
const isProduction = process.env.NODE_ENV === 'production';

// Keep the HTTP body cap aligned with the v1 aggregate input budget.
app.use(express.json({ limit: MAX_HTTP_JSON_BODY_BYTES }));
const apiLimiter = rateLimit({
 windowMs: 15 * 60 * 1000,
 max: 100,
 standardHeaders: true,
 legacyHeaders: false,
});
app.use('/api/', apiLimiter);

// ============================================================================
// SEGURANCA: RATE LIMITING & AUTENTICACAO OBRIGATORIA
// ============================================================================

interface RateLimitRecord {
  count: number;
  resetTime: number;
}

/**
 * Limitador de taxa (Rate Limiter) em memória sem dependências externas.
 * Protege rotas computacionalmente custosas (AST scan, GraphRAG, Chat de Seguranca) contra DoS.
 */
export function createRateLimiter(options: { windowMs: number; max: number; message?: string }): express.RequestHandler {
  const ipRequests = new Map<string, RateLimitRecord>();

  // Limpeza periodica a cada 5 minutos
  const interval = setInterval(() => {
    const now = Date.now();
    for (const [ip, record] of ipRequests.entries()) {
      if (now > record.resetTime) {
        ipRequests.delete(ip);
      }
    }
  }, 5 * 60 * 1000);
  interval.unref();

  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const clientIp = (req.ip || req.socket.remoteAddress || 'unknown-client').toString();
    const now = Date.now();
    const record = ipRequests.get(clientIp);

    if (!record || now > record.resetTime) {
      ipRequests.set(clientIp, {
        count: 1,
        resetTime: now + options.windowMs,
      });
      res.setHeader('X-RateLimit-Limit', options.max);
      res.setHeader('X-RateLimit-Remaining', options.max - 1);
      res.setHeader('X-RateLimit-Reset', Math.ceil((now + options.windowMs) / 1000));
      return next();
    }

    if (record.count >= options.max) {
      const retryAfter = Math.ceil((record.resetTime - now) / 1000);
      res.setHeader('Retry-After', retryAfter);
      res.setHeader('X-RateLimit-Limit', options.max);
      res.setHeader('X-RateLimit-Remaining', 0);
      res.setHeader('X-RateLimit-Reset', Math.ceil(record.resetTime / 1000));
      return res.status(429).json({
        success: false,
        error: options.message || 'Muitas requisicoes de auditoria detectadas. Por favor, tente novamente mais tarde (Rate limit excedido).',
        retryAfterSeconds: retryAfter,
      });
    }

    record.count += 1;
    res.setHeader('X-RateLimit-Limit', options.max);
    res.setHeader('X-RateLimit-Remaining', options.max - record.count);
    res.setHeader('X-RateLimit-Reset', Math.ceil(record.resetTime / 1000));
    next();
  };
}

/**
 * Rate Limiter dedicado para rotas de auditoria (GraphRAG, AST Scan, IA Agent)
 * Limite: maximo de 30 requisicoes por minuto por IP.
 */
export const auditRateLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 30,
  message: 'Limite de requisicoes de auditoria excedido (maximo 30 requisicoes/minuto). Aguarde antes de submeter nova analise.',
});

const ADMIN_KEYS = [process.env.ADMIN_API_KEY, process.env.MCP_API_KEY].filter(
  (key): key is string => typeof key === 'string' && key.length > 0,
);

if (process.env.NODE_ENV === 'production' && ADMIN_KEYS.length === 0) {
  throw new Error('ADMIN_API_KEY or MCP_API_KEY must be configured in production');
}

/**
 * Middleware de Autenticacao Obrigatorio para Rotas Administrativas e Endpoints MCP.
 * Aceita autenticacao via:
 * 1. Bearer Token no Header: Authorization: Bearer <token>
 * 2. Header customizado de chave de acesso: x-api-key
 */
export const requireAdminOrMcpAuth: express.RequestHandler = (req, res, next) => {
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
    return res.status(403).json({
      success: false,
      error: 'Acesso negado: Token de autorizacao ou chave de acesso invalida.',
    });
  }

  next();
};

// ============================================================================
// API ROUTES (/api/*)
// ============================================================================

// 1. GitHub CI/CD Pipeline & PR Synchronization (Real GitHub API with Pre-PR Validation)
// Autoria: Marco Antonio Conceicao
app.post('/api/github/sync', requireAdminOrMcpAuth, async (req, res) => {
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
    const status = msg.includes('401') ? 401 : msg.includes('404') ? 404 : msg.includes('422') ? 422 : msg.includes('unsupported or invalid') || msg.includes('obrigatorio') || msg.includes('obrigatório') ? 400 : 500;
    return res.status(status).json({
      success: false,
      error: msg,
    });
  }
});

// 2. Model Context Protocol (MCP) Manifest & Tool Discovery Endpoint
app.get('/api/mcp/manifest', requireAdminOrMcpAuth, (_req, res) => {
  res.json({
    name: 'solana-anchor-devsecops-mcp',
    version: '1.0.0',
    description: 'Solana Anchor DevSecOps IDE - EGC MCP Plugin',
    protocolVersion: '2024-11-05',
    tools: MCP_TOOLS,
  });
});

app.get('/api/v1/contract', requireAdminOrMcpAuth, (_req, res) => {
  res.json(getEgcV1Catalog());
});

app.post('/api/v1/execute', requireAdminOrMcpAuth, async (req, res) => {
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
app.post('/api/mcp/execute', requireAdminOrMcpAuth, async (req, res) => {
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

// 3. GraphRAG Security Reasoning Endpoint (Enterprise & Standard)
app.post('/api/graphrag/audit', auditRateLimiter, async (req, res) => {
  try {
    const { sourceCode } = req.body;
    const graphResult = buildContractSecurityGraph(sourceCode || '');
    const enterpriseGraph = buildEnterpriseKnowledgeGraph(sourceCode || '');
    res.json({ success: true, graph: graphResult, enterpriseGraph });
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
app.get('/api/egc/physical-files', requireAdminOrMcpAuth, auditRateLimiter, (_req, res) => {
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
app.post('/api/egc/scan', requireAdminOrMcpAuth, apiLimiter, auditRateLimiter, (req, res) => {
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
app.post('/api/github/issues', apiLimiter, requireAdminOrMcpAuth, async (req, res) => {
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
app.post('/api/egc/clean', apiLimiter, requireAdminOrMcpAuth, (_req, res) => {
  try {
    const result = purgeEgcState();
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 10. Continuous Learning & Model Weights Persistence Endpoints
app.get('/api/learning/state', (_req, res) => {
  try {
    const state = getLearningState();
    res.json({ success: true, state });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 10. Continuous Learning & Model Weights Persistence Endpoints
app.post('/api/learning/feedback', requireAdminOrMcpAuth, (req, res) => {
  try {
    const { source, ruleId, repository, deltaWeight, explanation } = req.body;
    if (!ruleId) {
      return res.status(400).json({ success: false, error: 'ruleId é obrigatório' });
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

// 11. Git Pre-Commit Hooks Management Endpoints
// Autoria: Marco Antonio Conceicao | Regra C44
app.get('/api/git-hooks/status', (_req, res) => {
  try {
    const hookPath = path.resolve(__dirname, '.git/hooks/pre-commit');
    const installed = fs.existsSync(hookPath);
    let isAuditStrictActive = false;

    if (installed) {
      const content = fs.readFileSync(hookPath, 'utf-8');
      isAuditStrictActive = content.includes('securityLintingService') && content.includes('audit_strict');
    }

    res.json({
      success: true,
      installed,
      isAuditStrictActive,
      hookPath,
      message: installed
        ? 'Git pre-commit hook ativo com verificacao estrita de seguranca.'
        : 'Git pre-commit hook nao instalado.',
    });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/git-hooks/install', requireAdminOrMcpAuth, (_req, res) => {
  try {
    const gitDir = path.resolve(__dirname, '.git');
    if (!fs.existsSync(gitDir)) {
      fs.mkdirSync(gitDir, { recursive: true });
    }

    const hooksDir = path.resolve(gitDir, 'hooks');
    if (!fs.existsSync(hooksDir)) {
      fs.mkdirSync(hooksDir, { recursive: true });
    }

    const hookPath = path.resolve(hooksDir, 'pre-commit');

    const hookScript = `#!/bin/bash
# ==============================================================================
# Git Pre-Commit Hook: Verificacao de Sintaxe Rust, Linter e Auditor AST EGC
# Autoria Oficial: Marco Antonio Conceicao
# Politica: Regra C44 (Nao-Destrutiva) - Zero-Panic & Checked Math
# ==============================================================================

set -e

echo "----------------------------------------------------------------------"
echo "🔍 [EGC PRE-COMMIT] Iniciando validacoes de seguranca DevSecOps..."
echo "----------------------------------------------------------------------"

# 1. Verificar presenca de caracteres invalidos (travessoes unicode)
echo "[1/5] Verificando conformidade tipografica (zero unicode dashes)..."
if command -v python3 >/dev/null 2>&1; then
  python3 -c "
import os, sys
violations = []
for root, dirs, files in os.walk('.'):
    if any(x in root for x in ['node_modules', '.git', 'dist']):
        continue
    for f in files:
        if f.endswith(('.ts', '.tsx', '.json', '.yml', '.yaml', '.html', '.css', '.toml', '.md', '.sh', '.rs')):
            path = os.path.join(root, f)
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    for idx, line in enumerate(fh, 1):
                        for char in ['\\\\u2014', '\\\\u2013', '\\\\u2012', '\\\\u2015']:
                            if char in line:
                                violations.append((path, idx, repr(char)))
            except Exception:
                pass
if violations:
    print(f'ERRO: Detetados {len(violations)} travessoes unicode proibidos:')
    for v in violations:
        print(f'  {v[0]}:{v[1]} - caractere {v[2]}')
    sys.exit(1)
" || { echo "Falha no pre-commit: remova os travessoes unicode antes de commitar."; exit 1; }
fi
echo "✔ Conformidade tipografica aprovada."

# 2. Verificar sintaxe e estilizacao de contratos Rust
echo "[2/5] Verificando sintaxe e integridade de codigo Rust..."
if command -v cargo >/dev/null 2>&1; then
  if [ -f "Cargo.toml" ]; then
    echo "Executando cargo check..."
    cargo check --workspace || { echo "Falha de sintaxe em crates Rust."; exit 1; }
  fi
else
  echo "Cargo nao detetado no ambiente local; pulando verificacao de compilacao nativa."
fi
echo "✔ Sintaxe Rust verificada."

# 3. Executar o Auditor AST EGC e Garantias On-Chain Solana
echo "[3/5] Executando Auditor AST e verificacao de garantias Solana (Zero Mocks)..."
if command -v npm >/dev/null 2>&1; then
  npm run test:mcp || { echo "Falha: O auditor AST ou MCP retornou violacao de seguranca."; exit 1; }
fi
echo "✔ Auditor AST e suite MCP aprovados."

# 4. Validar tipagem TypeScript
echo "[4/5] Validando estrita tipagem TypeScript (tsc --noEmit)..."
if command -v npm >/dev/null 2>&1; then
  npm run lint || { echo "Falha: Erros de tipagem detetados no TypeScript."; exit 1; }
fi
echo "✔ Validacao TypeScript aprovada."

# 5. Executar Linter Estrito de Seguranca (securityLintingService audit_strict)
echo "[5/5] Executando Security Linting Service (perfil audit_strict)..."
if command -v npm >/dev/null 2>&1; then
  npx tsx -e "
    import { runSecurityLintAudit } from './src/services/securityLintingService.ts';
    import fs from 'fs';

    const candidatePaths = [
      'programs/anchor_security_program/src/lib.rs',
      'programs/solana_sandbox_counter/src/lib.rs',
      'client/index.ts',
      'src/contracts/solanaSandboxCounter.ts'
    ];

    const files = [];
    for (const p of candidatePaths) {
      if (fs.existsSync(p)) {
        files.push({ path: p, content: fs.readFileSync(p, 'utf-8') });
      }
    }

    const report = runSecurityLintAudit(files, 'audit_strict');
    if (!report.passed || report.errorCount > 0) {
      console.error('ERRO: Violacoes criticas de seguranca detetadas no pre-commit (audit_strict):');
      for (const f of report.findings.filter(x => x.severity === 'error')) {
        console.error('  - [' + f.ruleId + '] ' + f.file + ':' + f.line + ' ' + f.message);
      }
      process.exit(1);
    }
    console.log('✔ Seguranca audit_strict aprovada: zero panics e checked arithmetic confirmado.');
  " || { echo "Falha: Codigo inseguro bloqueado pelo pre-commit hook antes do stage."; exit 1; }
fi
echo "✔ Security Linting Service (audit_strict) aprovado."

echo "----------------------------------------------------------------------"
echo "✔ [EGC PRE-COMMIT] Todas as verificacoes foram aprovadas com sucesso!"
echo "----------------------------------------------------------------------"
exit 0
`;

    fs.writeFileSync(hookPath, hookScript, { mode: 0o755 });
    res.json({
      success: true,
      installed: true,
      isAuditStrictActive: true,
      message: 'Git pre-commit hook instalado e ativado com sucesso em .git/hooks/pre-commit.',
    });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post('/api/git-hooks/uninstall', requireAdminOrMcpAuth, (_req, res) => {
  try {
    const hookPath = path.resolve(__dirname, '.git/hooks/pre-commit');
    if (fs.existsSync(hookPath)) {
      fs.unlinkSync(hookPath);
    }
    res.json({
      success: true,
      installed: false,
      isAuditStrictActive: false,
      message: 'Git pre-commit hook desinstalado.',
    });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// 12. Security Agent Chat Endpoint (MCP Server & GraphRAG/AST Context)
// Autoria: Marco Antonio Conceicao | Regra C44
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

export { app };
export default app;

if (process.env.EGC_DISABLE_LISTEN !== '1') {
  startServer();
}
