# Solana Anchor DevSecOps IDE - Model Context Protocol (MCP) & EGC Plugin

Este módulo implementa o servidor MCP (Model Context Protocol) e o adaptador de execução compatível com o **EGC (Extended Global Context)** para integrar o ecossistema Solana Anchor DevSecOps em qualquer sessão de IA (como **Cursor**, **Claude Code** ou agentes autônomos).

---

## 🛠️ Ferramentas Disponíveis no MCP

| Ferramenta | Descrição |
|---|---|
| `generate_anchor_contract` | Gera código seguro em Rust/Anchor com contas PDA determinísticas, aritmética protegida (`checked_add`/`checked_sub`), verificação de autoridade (`has_one = authority`) e cálculo exato de rent-exempt (49 bytes). |
| `audit_rust_ast` | Executa análise estática de segurança AST diretamente no código Rust/Anchor, detetando falhas de signatários, ausência de verificação de bump, vulnerabilidades aritméticas e discrepâncias de memória. |
| `create_github_pr` | Cria e abre um Pull Request no repositório remoto do GitHub com o contrato e a pipeline DevSecOps. **Merge automático desativado**: requer aprovação manual estrita no GitHub e validação obrigatória do PAT (`ghp_` ou `github_pat_`). |
| `run_property_fuzzer` | Executa até 20.000 vetores de fuzzing baseados em propriedades validando invariantes na SVM Solana. |
| `derive_pda_spec` | Deriva o endereço off-curve PDA, bump canónico e valida os 49 bytes exatos para rent-exempt. |
| `query_graphrag_security` | Consulta o grafo GraphRAG de caminhos de ataque e dependências entre instruções Solana. |

---

## 🚀 Como Testar Localmente (Plug-and-Play)

Para o **Felipe Marzock** ou qualquer membro da equipa testar o fluxo na sua máquina local:

### 1. Executar a Suite de Testes Automatizada
```bash
npm run test:mcp
```
Esta suite testa a integridade do manifesto, a geração de contratos, o motor AST e a validação estrita de segurança e bloqueio de tokens do GitHub.

### 2. Iniciar o Servidor MCP via Stdio (Padrão Cursor / Claude Code)
```bash
npm run mcp
```
Ou diretamente:
```bash
npx tsx src/mcp/cli.ts
```

---

## 🔌 Configuração no Cursor e Claude Code

### Cursor IDE (`.cursor/mcp.json` ou Configurações do Cursor)
O repositório já inclui o ficheiro `mcp.json` e `.cursor/mcp.json` pré-configurado:
```json
{
  "mcpServers": {
    "solana-anchor-devsecops": {
      "command": "npx",
      "args": ["tsx", "src/mcp/cli.ts"],
      "env": {
        "NODE_ENV": "development"
      }
    }
  }
}
```

### Claude Desktop (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "solana-anchor-devsecops": {
      "command": "npx",
      "args": ["tsx", "/caminho/para/o/projeto/src/mcp/cli.ts"]
    }
  }
}
```

---

## 🔒 Isolamento e Segurança Local (EGC)
- **Execução In-Process:** Todos os motores de auditoria AST, derivação PDA e geração de código correm localmente no processo Node.js / TypeScript, sem transmissão de código para serviços externos.
- **Validação de Credenciais:** Tokens do GitHub são transmitidos unicamente no momento de criação de PR para a API oficial do GitHub (`api.github.com`), com verificação de formato e exigência de merge manual.
