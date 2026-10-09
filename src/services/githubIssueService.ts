/**
 * GitHub Issues Creation Service for Solana Anchor DevSecOps
 * Modulo: src/services/githubIssueService.ts
 * Autoria: Marco Antonio Conceicao
 *
 * Cria e despacha issues reais diretamente na API do GitHub para cada
 * vulnerabilidade ou item auditado pelo motor de varredura real.
 */

import { RealScanFinding } from './realRepoScanner.ts';
import { validateGitHubToken } from './githubPrService.ts';
import { ContextualRepositoryArchitecture, enrichFindingWithContext } from './contextualEngine.ts';

export interface CreateGitHubIssuesOptions {
  token: string;
  owner: string;
  repoName: string;
  findings: RealScanFinding[];
  context?: ContextualRepositoryArchitecture;
}

export interface CreatedGitHubIssue {
  id: number;
  number: number;
  title: string;
  htmlUrl: string;
  state: string;
  findingId: string;
  severity: string;
}

export interface CreateGitHubIssuesResult {
  success: boolean;
  totalCreated: number;
  issues: CreatedGitHubIssue[];
  errors: string[];
  message: string;
}

/**
 * Cria issues reais no repositorio remoto do GitHub via API REST.
 */
export async function createRealGitHubIssues(
  options: CreateGitHubIssuesOptions
): Promise<CreateGitHubIssuesResult> {
  const { token, owner, repoName, findings, context } = options;

  // 1. Validacao previa do token
  const tokenValidation = validateGitHubToken(token);
  if (!tokenValidation.valid) {
    throw new Error(tokenValidation.error || 'Token de acesso do GitHub invalido');
  }

  if (!owner || !owner.trim()) {
    throw new Error('O proprietario (owner) do repositorio e obrigatorio.');
  }

  if (!repoName || !repoName.trim()) {
    throw new Error('O nome do repositorio (repoName) e obrigatorio.');
  }

  // Filtrar findings acionaveis (excluir os que passaram PASS a menos que nao haja nenhum)
  const actionableFindings = findings.filter(f => f.severity !== 'PASS');
  const targetFindings = actionableFindings.length > 0 ? actionableFindings : findings.slice(0, 2);

  const createdIssues: CreatedGitHubIssue[] = [];
  const errors: string[] = [];

  const headers: Record<string, string> = {
    Authorization: `Bearer ${token.trim()}`,
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'Solana-Anchor-DevSecOps-IDE',
    'Content-Type': 'application/json',
  };

  for (const finding of targetFindings) {
    const contextualSection = context ? enrichFindingWithContext(finding, context) : '';
    const issueTitle = `🛡️ [Solana DevSecOps] ${finding.severity}: ${finding.title}`;
    const issueBody = `## Relatorio de Auditoria de Seguranca Solana Anchor
**Autoria da Auditoria:** Marco Antonio Conceicao
**Categoria:** ${finding.category}
**Nivel de Severidade:** ${finding.severity}
**Arquivo:** \`${finding.file}\` (Linha: ${finding.line})
**Regra ID:** \`${finding.ruleId}\`

### 🔍 Descricao da Vulnerabilidade
${finding.description}

${finding.snippet ? `### 📝 Trecho Inspecionado\n\`\`\`rust\n${finding.snippet}\n\`\`\`\n` : ''}
${contextualSection}
### 💡 Recomendacao de Seguranca
${finding.recommendation}

${finding.remediationCode ? `### 🛠️ Codigo de Remediacao Sugerido (Regra C44 - Nao-Destrutivo)\n\`\`\`rust\n${finding.remediationCode}\n\`\`\`\n` : ''}

---
*Gerado com Engenharia Contextual (GraphRAG, DDD, SOA & AST) pelo Centro de Comando EGC.*`;

    const labels = ['security', 'solana', 'anchor-lang', 'audit', finding.severity.toLowerCase()];

    try {
      const response = await fetch(`https://api.github.com/repos/${owner.trim()}/${repoName.trim()}/issues`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          title: issueTitle,
          body: issueBody,
          labels,
        }),
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        const err = data.message || `HTTP ${response.status}`;
        errors.push(`Falha ao criar issue "${finding.title}": ${err}`);
      } else {
        createdIssues.push({
          id: data.id,
          number: data.number,
          title: data.title,
          htmlUrl: data.html_url,
          state: data.state,
          findingId: finding.id,
          severity: finding.severity,
        });
      }
    } catch (err: any) {
      errors.push(`Excecao na requisicao de issue para ${finding.id}: ${err.message}`);
    }
  }

  const success = createdIssues.length > 0 || errors.length === 0;
  const message = createdIssues.length > 0
    ? `${createdIssues.length} issues reais criadas com sucesso no GitHub!`
    : `Nenhuma issue criada. Erros encontrados: ${errors.join('; ')}`;

  return {
    success,
    totalCreated: createdIssues.length,
    issues: createdIssues,
    errors,
    message,
  };
}
