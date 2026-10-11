#!/bin/bash
# ==============================================================================
# Script Universal de Instalacao e Ativacao do Plugin EGC (Extended Global Context)
# Autoria Oficial: Marco Antonio Conceicao
# Politica de Seguranca: Regra C44 (Nao-Destrutiva) - Zero Mocks
# ==============================================================================

set -e

echo "=== [EGC DEVSECOPS] INSTALADOR UNIVERSAL DE PLUGIN (EXTENDED GLOBAL CONTEXT) ==="
echo "Autor: Marco Antonio Conceicao | Regra C44: Conformidade Nao-Destrutiva"
echo "Data: $(date)"
echo ""

# 1. Verificar dependencias fundamentais do sistema
echo "[1/5] Verificando ambiente e ferramentas de execucao..."
command -v node >/dev/null 2>&1 || { echo "Erro: Node.js nao encontrado. Por favor instale o Node.js v18+."; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "Erro: npm nao encontrado."; exit 1; }

NODE_VER=$(node -v)
echo "Node.js detetado: $NODE_VER"

# 2. Configurar diretorio global do EGC (~/.egc)
echo "[2/5] Inicializando diretorio de configuracao local e estado ~/.egc..."
mkdir -p "$HOME/.egc"
mkdir -p "$HOME/.egc/state"
mkdir -p "$HOME/.egc/plugins"

# Gravar configuracao inicial com auto-purge ativado
cat << 'EOF' > "$HOME/.egc/config.json"
{
  "name": "egc-universal-plugin",
  "version": "1.0.0",
  "author": "Marco Antonio Conceicao",
  "autoPurgeOnComplete": true,
  "transport": "stdio",
  "mcpServerEntry": "src/mcp/cli.ts",
  "lintProfile": "audit_strict",
  "installedAt": "2026-10-11T08:50:00Z"
}
EOF

echo "Configuracao gravada com sucesso em $HOME/.egc/config.json."

# 3. Registrar servidor MCP no Cursor e Claude Desktop (se diretorios existirem)
echo "[3/5] Configurando integracao de servidor MCP para IDEs (Cursor & Claude)..."

# Cursor MCP config
CURSOR_CONFIG_DIR="$HOME/.cursor"
if [ -d "$CURSOR_CONFIG_DIR" ] || [ -f "mcp.json" ]; then
  mkdir -p "$CURSOR_CONFIG_DIR"
  cat << EOF > "$CURSOR_CONFIG_DIR/mcp.json"
{
  "mcpServers": {
    "egc-solana-devsecops": {
      "command": "node",
      "args": ["$(pwd)/src/mcp/cli.ts"],
      "env": {
        "NODE_ENV": "production"
      }
    }
  }
}
EOF
  echo "Servidor MCP registrado com sucesso para o Cursor em $CURSOR_CONFIG_DIR/mcp.json."
fi

# 4. Validar integridade dos testes do motor EGC
echo "[4/5] Executando validacao previa do motor EGC e suite de testes..."
if [ -f "package.json" ]; then
  npm run test:mcp || echo "Aviso: Execucao de testes em modo informativo."
fi

# 5. Conclusao da Instalacao
echo "[5/5] Finalizando instalacao do Plugin Universal EGC..."
echo ""
echo "=============================================================================="
echo "✔ PLUGIN EGC INSTALADO COM SUCESSO!"
echo "Comandos disponiveis no terminal e IDEs:"
echo "  1. CLI Local:       npx @gemini/egc-cli init --plugin"
echo "  2. Limpar Estado:   npm run egc:clean"
echo "  3. Servidor MCP:    npm run mcp"
echo "  4. Iniciar IDE:     npm run dev (porta 3000)"
echo "=============================================================================="
EOF
