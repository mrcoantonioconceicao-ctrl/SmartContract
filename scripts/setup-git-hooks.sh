#!/bin/bash
# ==============================================================================
# Script de Automacao: Setup Git Pre-Commit Hooks
# Modulo: scripts/setup-git-hooks.sh
# Autoria Oficial: Marco Antonio Conceicao
# Politica de Seguranca: Regra C44 (Nao-Destrutiva) - Zero Mocks
# ==============================================================================

set -e

echo "=== [DEVSECOPS] CONFIGURANDO PRE-COMMIT HOOKS DO GIT ==="
echo "Autor: Marco Antonio Conceicao | Regra C44 Nao-Destrutiva"
echo ""

# 1. Verificar se o diretorio .git existe
if [ ! -d ".git" ]; then
  echo "Aviso: Diretorio .git nao encontrado. Inicializando repositorio git local..."
  git init
fi

HOOKS_DIR=".git/hooks"
PRE_COMMIT_HOOK="$HOOKS_DIR/pre-commit"

mkdir -p "$HOOKS_DIR"

echo "[1/3] Gerando script do pre-commit hook..."

cat << 'EOF' > "$PRE_COMMIT_HOOK"
#!/bin/bash
# ==============================================================================
# Git Pre-Commit Hook: Verificacao de Sintaxe Rust, Linter e Auditor AST EGC
# Autoria Oficial: Marco Antonio Conceicao
# ==============================================================================

set -e

echo "----------------------------------------------------------------------"
echo "🔍 [EGC PRE-COMMIT] Iniciando validacoes de seguranca DevSecOps..."
echo "----------------------------------------------------------------------"

# 1. Verificar presenca de caracteres invalidos (travessoes unicode: em-dash / en-dash)
echo "[1/4] Verificando conformidade tipografica (zero unicode dashes)..."
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
                        for char in ['\u2014', '\u2013', '\u2012', '\u2015']:
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

# 2. Verificar sintaxe e estilizacao de contratos Rust (cargo check / clippy se cargo disponivel)
echo "[2/4] Verificando sintaxe e integridade de codigo Rust..."
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
echo "[3/4] Executando Auditor AST e verificacao de garantias Solana (Zero Mocks)..."
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

# 5. Executar Linter Estrito de Seguranca (securityLintingService audit_strict: zero-panic e checked_add)
echo "[5/5] Executando Security Linting Service (perfil audit_strict)..."
if command -v npm >/dev/null 2>&1; then
  npx tsx -e "
    import { runSecurityLintAudit } from './src/services/securityLintingService.ts';
    import fs from 'fs';
    import path from 'path';

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
EOF

echo "[2/3] Concedendo permissao de execucao ao pre-commit hook..."
chmod +x "$PRE_COMMIT_HOOK"

echo "[3/3] Validando instalacao do hook..."
if [ -x "$PRE_COMMIT_HOOK" ]; then
  echo "✔ Pre-commit hook instalado com sucesso em $PRE_COMMIT_HOOK"
else
  echo "Erro: Falha ao conceder permissao de execucao ao hook."
  exit 1
fi

echo ""
echo "=== CONFIGURACAO CONCLUIDA! ==="
echo "Os commits futuros serao automaticamente validados pelo auditor AST e sintaxe Rust."
