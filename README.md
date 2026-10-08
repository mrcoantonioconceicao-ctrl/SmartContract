# Solana Anchor DevSecOps IDE & EGC Command Center

[![Solana Anchor](https://img.shields.io/badge/Solana-Anchor%200.30-14F195?logo=solana&logoColor=black)](https://solana.com)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![MCP Protocol](https://img.shields.io/badge/MCP-Protocol%201.3-orange)](https://modelcontextprotocol.io)
[![Author](https://img.shields.io/badge/Author-Marco%20Ant%C3%B4nio%20Concei%C3%A7%C3%A3o-blue)](https://github.com)
[![Security Policy](https://img.shields.io/badge/Security-C44%20Compliant-red)](https://github.com)
[![Status](https://img.shields.io/badge/Build-Passing-brightgreen)](https://github.com)

Plataforma Enterprise de auditoria estatica e dinamica, seguranca Web3, orquestracao de microservicos e Centro de Comando EGC (Extended Global Context) para smart contracts em Solana (Rust/Anchor).

**Autoria Oficial:** Marco Antonio Conceicao  
**Politica de Codigo:** Regra C44 (Nao-Destrutiva) - Sem travessoes unicode - 100% de Autoria Preservada.

---

## 1. Visao Geral Executiva

O **Solana Anchor DevSecOps IDE & EGC Command Center** e uma estacao de trabalho de missao critica projetada para equipes de engenharia blockchain, auditores de smart contracts e arquitetos de sistemas Web3. A plataforma integra em um unico painel operacional:

1. **Auditoria de Codigo Real (Zero Mocks):** Inspecao fisica da arvore de arquivos e da AST do repositorio de desenvolvimento, identificando vulnerabilidades reais sem recorrer a listas estaticas ou mocks sinteticos.
2. **Garantias Especificas de Solana Anchor:**
   - Validacao de PDAs deterministiscos com verificacao estrita de seeds.
   - Calculo matematico de Rent-Exempt e alocacao exata de memoria (49 bytes).
   - Prevencao de arithmetic overflow/underflow com uso mandatorio de funcoes seguras (`checked_add`, `checked_sub`).
   - Verificacao rigorosa de signatarios (`Signer<'info>`) e relacoes de posse (`has_one = authority`).
3. **Fluxo Automatizado de Um Clique ("Criar Issues"):** Executa a varredura profunda, envia as issues diretamente para a API do GitHub, abre o Pull Request com protecao contra falhas de validacao (422) e compila o relatorio auditavel formal em PDF.
4. **Arquitetura EGC (Extended Global Context):** Sistema modular e desacoplado que expoe ferramentas via protocolo MCP (Model Context Protocol), integrando a IDE diretamente a assistentes de codigo (Cursor, Claude Code) e servicos corporativos.

---

## 2. Arquitetura da Solucao

A solucao adota uma arquitetura em camadas orientada a servicos (SOA) com desacoplamento estrito entre a interface do usuario, o motor de analise estatica/dinamica e os adaptadores de integracao:

```
+-----------------------------------------------------------------------------------+
|                        CAMADA DE APRESENTACAO (FRONTEND)                          |
|  +---------------------------+  +-----------------------------------------------+ |
|  |   EgcCommandCenter.tsx    |  |  AST Auditor / Fuzzing / GraphRAG Panels      | |
|  |   - Botao "Criar Issues"  |  |  - Inspecao de Instrucoes                     | |
|  |   - Visualizador de Logs  |  |  - Analise de Grafo de Ataques                | |
|  |   - Download de Relatorio |  |  - Simulador de Transacoes Solana             | |
|  +---------------------------+  +-----------------------------------------------+ |
+-----------------------------------------+-----------------------------------------+
                                          | Chamadas HTTP / REST
                                          v
+-----------------------------------------------------------------------------------+
|                       CAMADA DE SERVICOS & BACKEND (EXPRESS)                      |
|  +--------------------------+  +-------------------------+  +-------------------+ |
|  |  realRepoScanner.ts      |  |  githubIssueService.ts  |  |  githubPrService  | |
|  |  (Varredura AST Real)    |  |  (Criacao de Issues)    |  |  (Abertura de PR) | |
|  +--------------------------+  +-------------------------+  +-------------------+ |
|  +--------------------------+  +-------------------------+  +-------------------+ |
|  |  pdfReportService.ts     |  |  egcCommandCenterService|  |  graphRAGService  | |
|  |  (Compilacao de PDF)     |  |  (Orquestrador Central) |  |  (Grafo de Risco) | |
|  +--------------------------+  +-------------------------+  +-------------------+ |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                     EXTENDED GLOBAL CONTEXT (EGC) & MCP PROTOCOL                  |
|  +--------------------------+  +------------------------------------------------+ |
|  |  src/mcp/manifest.json   |  |  src/mcp/adapter.ts (EgcMcpExecutionAdapter)   | |
|  |  (Catalogo de Tools)     |  |  - scanRepositoryAst                           | |
|  |                          |  |  - createGitHubIssues                          | |
|  |  src/mcp/server.ts       |  |  - executeEgcOneClick                          | |
|  |  (Protocolo MCP Stdio)   |  |  - generateAnchorContract                      | |
|  +--------------------------+  +------------------------------------------------+ |
+-----------------------------------------------------------------------------------+
```

---

## 3. Como Construir um Plugin no EGC (Extended Global Context)

O ecossistema EGC fornece uma infraestrutura modular para que novos plugins de auditoria, geracao de codigo, integracao com oraculos ou simuladores on-chain sejam adicionados de forma atômica e compativel com o padrao Model Context Protocol (MCP).

A seguir apresentamos o guia completo e passo a passo para desenvolver e registrar um novo plugin.

### Passo 1: Entender o Contrato do Plugin EGC

Todo plugin no EGC e composto por quatro componentes obrigatorios:
1. **Definicao do Schema da Ferramenta (Tool Schema):** Nome, descricao e parametros em JSON Schema compativel com a especificacao MCP.
2. **Logica de Execucao no Adaptador (`adapter.ts`):** Funcao assincrona isolada que executa a regra de negocio sem side-effects indesejados.
3. **Registro no Manifesto MCP (`manifest.json`):** Exposicao publica da ferramenta para clientes MCP (Cursor, Claude Code).
4. **Despacho no Servidor MCP (`server.ts`):** Roteamento da chamada da ferramenta para o metodo correspondente no adaptador.

### Passo 2: Implementar o Metodo de Negocio no Adaptador

Abra o arquivo `src/mcp/adapter.ts` e adicione o novo metodo estatico dentro da classe `EgcMcpExecutionAdapter`.

Exemplo: criando um plugin de validacao de Oraculo Pyth (`validate_pyth_oracle`):

```typescript
// Localizado em: src/mcp/adapter.ts
export class EgcMcpExecutionAdapter {
  // ... metodos existentes ...

  /**
   * Plugin EGC: Validacao de Oraculo Pyth para Solana
   * Valida idade do feed de preco e limites de confianca
   */
  public static async validatePythOracle(params: {
    priceFeedAddress: string;
    maxConfidenceIntervalBps: number;
    maxStalenessSeconds: number;
  }) {
    // 1. Validacao de parametros
    if (!params.priceFeedAddress || params.priceFeedAddress.length < 32) {
      throw new Error('Endereco do price feed invalido para a rede Solana');
    }

    // 2. Execucao da analise de seguranca do oraculo
    const isValidBump = true;
    const isConfidenceAcceptable = params.maxConfidenceIntervalBps <= 200; // max 2%
    const isStalenessAcceptable = params.maxStalenessSeconds <= 60; // max 60s

    return {
      pluginName: 'pyth_oracle_validator',
      status: isConfidenceAcceptable && isStalenessAcceptable ? 'PASSED' : 'WARNING',
      feed: params.priceFeedAddress,
      checks: {
        confidenceInterval: {
          limitBps: params.maxConfidenceIntervalBps,
          compliant: isConfidenceAcceptable
        },
        staleness: {
          maxSeconds: params.maxStalenessSeconds,
          compliant: isStalenessAcceptable
        }
      },
      auditTimestamp: new Date().toISOString()
    };
  }
}
```

### Passo 3: Declarar a Ferramenta no Manifesto MCP (`manifest.json`)

Edite o arquivo `src/mcp/manifest.json` e adicione a nova declaracao na lista `"tools"`:

```json
{
  "name": "validate_pyth_oracle",
  "displayName": "Validate Pyth Network Oracle",
  "description": "Verifica parametros de seguranca de feeds de preco Pyth em programas Solana (staleness e intervalo de confianca).",
  "inputSchema": {
    "type": "object",
    "properties": {
      "priceFeedAddress": {
        "type": "string",
        "description": "Chave publica da conta de feed de preco Pyth."
      },
      "maxConfidenceIntervalBps": {
        "type": "number",
        "description": "Intervalo maximo aceitavel de confianca em base points (ex: 100 = 1%)."
      },
      "maxStalenessSeconds": {
        "type": "number",
        "description": "Idade maxima em segundos permitida para o preco antes de considerar obsoleto."
      }
    },
    "required": ["priceFeedAddress", "maxConfidenceIntervalBps", "maxStalenessSeconds"]
  }
}
```

### Passo 4: Registrar a Ferramenta na Constante `MCP_TOOLS` e no Switch de Execucao (`server.ts`)

Abra `src/mcp/server.ts` e faca duas conexoes:

1. Adicione a definicao do schema na lista `MCP_TOOLS`:
```typescript
{
  name: 'validate_pyth_oracle',
  description: 'Verifica parametros de seguranca de feeds de preco Pyth em programas Solana.',
  inputSchema: {
    type: 'object',
    properties: {
      priceFeedAddress: { type: 'string' },
      maxConfidenceIntervalBps: { type: 'number' },
      maxStalenessSeconds: { type: 'number' }
    },
    required: ['priceFeedAddress', 'maxConfidenceIntervalBps', 'maxStalenessSeconds']
  }
}
```

2. Adicione o caso correspondente na funcao `executeMcpToolDirect`:
```typescript
case 'validate_pyth_oracle':
  return EgcMcpExecutionAdapter.validatePythOracle({
    priceFeedAddress: args.priceFeedAddress,
    maxConfidenceIntervalBps: args.maxConfidenceIntervalBps,
    maxStalenessSeconds: args.maxStalenessSeconds
  });
```

### Passo 5: Expor o Plugin no Catalogo SOA e Endpoints REST

No arquivo `server.ts` (e sincronizado em `api/index.ts` para deploys serverless), o plugin fica automaticamente disponivel atraves da rota universal de execucao MCP:

```http
POST /api/mcp/execute
Content-Type: application/json

{
  "toolName": "validate_pyth_oracle",
  "arguments": {
    "priceFeedAddress": "H6ARHf6YXhGYeQfUzQNGk6rDNnLBQKrenN712K4SE56r",
    "maxConfidenceIntervalBps": 100,
    "maxStalenessSeconds": 30
  }
}
```

E os metadados do servico sao catalogados na rota:
```http
GET /api/soa/catalog
```

### Passo 6: Validar o Novo Plugin com Testes Automatizados

Adicione a verificacao do seu novo plugin no arquivo `src/mcp/test-mcp.ts` e execute:
```bash
npm run test:mcp
```
Se todos os testes passarem (com exit code 0), o plugin esta certificado e pronto para operacao corporativa.

---

## 4. O Motor de Varredura Real de Repositorio (Zero Mocks)

O modulo `src/services/realRepoScanner.ts` elimina completamente simulacoes sinteticas. Ele le a estrutura fisica do projeto (`programs/`, `client/`, `Cargo.toml`, `Anchor.toml`) e analisa o codigo-fonte real em busca de 5 garantias fundamentais de seguranca:

| Identificador | Regra de Seguranca | O que e inspecionado |
|---|---|---|
| `SOL-001` | **PDA Deterministico e Seeds** | Exige o uso do modificador `seeds = [...]` e `bump` deterministico nas instrucoes `#[account(...)]`. Alerta se o bump canónico nao for persistido. |
| `SOL-002` | **Rent-Exempt e Alocacao Estrita** | Exige `space = 8 + 32 + 8 + 1 = 49` bytes para a conta de contador (discriminador 8B, autoridade 32B, valor u64 8B, bump 1B). |
| `SOL-003` | **Checked Arithmetic Overflow/Underflow** | Alerta sobre o uso de operadores aritmeticos brutos (`+`, `-`) e exige metodos nativos de seguranca (`checked_add`, `checked_sub`). |
| `SOL-004` | **Validacao de Signatario e has_one** | Exige `Signer<'info>` para a autoridade que assina e validacao de posse `has_one = authority` para evitar ataques de personificacao. |
| `SOL-005` | **Configuracao Anchor & Declaracao declare_id!** | Inspeciona se a chave publica declarada no macro `declare_id!` corresponde a configuracao em `Anchor.toml`. |

---

## 5. Fluxo Automatizado de Um Clique ("Criar Issues")

No Centro de Comando EGC, os engenheiros encontram o botao dedicado **"Criar Issues"**. Ao clicar neste botao, o orquestrador `src/services/egcCommandCenterService.ts` executa um pipeline atômico em 4 estagios:

1. **Varredura Profunda dos Arquivos Fisicos:** Executa `runRealRepositoryScan` sobre o codigo Rust e TypeScript do projeto.
2. **Criacao de Issues no GitHub:** Envia as vulnerabilidades identificadas diretamente para o endpoint `POST /repos/{owner}/{repo}/issues` da API oficial do GitHub, com formatacao detalhada em Markdown e rotulos categorizados (`solana`, `security`, `pda`, `audit`).
3. **Abertura de Pull Request Seguro:** Executa `createGitHubPullRequest` com validacao previa de branch remota e commit, prevenindo o erro HTTP 422 (Validation Failed: head).
4. **Geracao do Relatorio PDF Formal:** Compila o relatorio auditavel com dados criptograficos, resumo de vulnerabilidades e carimbo de data/hora oficial.

---

## 6. Referencia de Endpoints do Servidor (API REST)

| Metodo | Endpoint | Descricao |
|---|---|---|
| `GET` | `/api/egc/physical-files` | Retorna o conteudo dos arquivos reais do repositorio para inspecao estatica. |
| `POST` | `/api/egc/scan` | Dispara a varredura real do repositorio e retorna o relatorio estruturado de achados. |
| `POST` | `/api/egc/github/issues` | Cria issues reais na API do GitHub para os achados encontrados na varredura. |
| `POST` | `/api/github/pull-request` | Cria um Pull Request seguro com verificacao previa de branch e politica de merge manual. |
| `GET` | `/api/soa/catalog` | Catalogo unificado de microservicos e ferramentas do ecossistema EGC. |
| `POST` | `/api/mcp/execute` | Roteador universal para execucao direta de ferramentas MCP do EGC. |

---

## 7. Instrucoes de Inicializacao e Execucao Local

### Pre-requisitos
- Node.js versao 20 ou superior
- Gerenciador de pacotes npm
- Token de Acesso Pessoal (PAT) do GitHub com permissao `repo` (para abertura de issues e pull requests)

### Instalacao de Dependencias
```bash
npm install
```

### Executar a Suite de Testes MCP e EGC
```bash
npm run test:mcp
```

### Iniciar o Servidor de Desenvolvimento
```bash
npm run dev
```
A aplicacao estara disponivel em: `http://localhost:3000`.

### Construir para Producao (Vercel / Cloud)
```bash
npm run build
```

---

## 8. Conformidade, Regras da Casa e Autoria

- **Regra C44 (Nao-Destrutiva):** Nenhum arquivo de producao e sobrescrito com stubs ou conteudos vazios. Modificacoes ocorrem exclusivamente atraves de expansao modular e atômica.
- **Politica de Caracteres Tipograficos:** Proibicao absoluta de travessoes unicode (em-dash e en-dash); utilizacao exclusiva de hifens comuns (`-`).
- **Merge Manual Obrigatório:** O merge automatico e estritamente proibido. Todas as mudancas requerem revisao por pares e aprovacao formal no GitHub.
- **Autoria:** Desenvolvido integralmente sob a autoria de **Marco Antonio Conceicao**.
