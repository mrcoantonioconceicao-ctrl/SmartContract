/**
 * GitHub Pull Request Service
 * Strictly enforces real GitHub API calls, mandatory PAT validation,
 * and manual-only merge policy (no auto-merge allowed).
 */

export interface CreateGitHubPrOptions {
  token: string;
  owner: string;
  repoName: string;
  branchName?: string;
  title?: string;
  body?: string;
  contractCode?: string;
}

export interface GitHubPrResult {
  success: boolean;
  mode: 'live_github_api';
  prStatus: 'OPEN';
  manualMergeRequired: true;
  autoMergeEnabled: false;
  prUrl: string;
  prNumber: number;
  owner: string;
  repo: string;
  branch: string;
  message: string;
}

/**
 * Validates GitHub Personal Access Token format
 */
export function validateGitHubToken(token?: string): { valid: boolean; error?: string } {
  if (!token || typeof token !== 'string' || !token.trim()) {
    return {
      valid: false,
      error: 'O GitHub Personal Access Token (PAT) é obrigatório. Forneça um token válido com permissões de repositório (ex: ghp_... ou github_pat_...).',
    };
  }

  const trimmed = token.trim();
  if (!trimmed.startsWith('ghp_') && !trimmed.startsWith('github_pat_')) {
    return {
      valid: false,
      error: 'Formato do GitHub Personal Access Token inválido. Os tokens do GitHub devem iniciar com "ghp_" (Classic) ou "github_pat_" (Fine-grained).',
    };
  }

  return { valid: true };
}

/**
 * Creates and opens a Pull Request on a remote GitHub repository.
 * Guarantees no auto-merge is invoked; strictly keeps state 'open' for manual review.
 */
export async function createGitHubPullRequest(options: CreateGitHubPrOptions): Promise<GitHubPrResult> {
  const { token, owner, repoName, branchName, title, body, contractCode } = options;

  // 1. Validate Token
  const tokenValidation = validateGitHubToken(token);
  if (!tokenValidation.valid) {
    throw new Error(tokenValidation.error);
  }

  const trimmedToken = token.trim();
  const targetOwner = (owner || '').trim();
  const targetRepo = (repoName || '').trim();
  const branch = (branchName || `devsecops/anchor-pda-${Date.now().toString(36)}`).trim();

  if (!targetOwner) {
    throw new Error('O utilizador ou organização do GitHub é obrigatório.');
  }

  if (!targetRepo) {
    throw new Error('O nome do repositório de destino é obrigatório.');
  }

  const headers = {
    Authorization: `Bearer ${trimmedToken}`,
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'Solana-Anchor-DevSecOps-IDE',
  };

  // 2. Validate repository access via real GitHub API
  const repoCheckResponse = await fetch(`https://api.github.com/repos/${targetOwner}/${targetRepo}`, {
    headers,
  });

  if (!repoCheckResponse.ok) {
    const status = repoCheckResponse.status;
    const repoErr = await repoCheckResponse.json().catch(() => ({}));
    if (status === 401) {
      throw new Error('GitHub Token inválido ou expirado (HTTP 401 Unauthorized). Verifique o seu Personal Access Token.');
    }
    if (status === 404) {
      throw new Error(`Repositório "${targetOwner}/${targetRepo}" não encontrado (HTTP 404 Not Found) ou o token não possui permissões de acesso ao mesmo.`);
    }
    throw new Error(`Erro de acesso ao repositório GitHub (${status}): ${repoErr.message || 'Falha ao consultar repositório'}`);
  }

  // 3. Prepare PR markdown body with security badges and manual approval notice
  const prTitle = title || '🛡️ [DevSecOps] Deploy Secure Anchor Counter';
  const prDescription = [
    body || 'Audited by GraphRAG and AST engine.',
    contractCode ? `\n\n### Audited Anchor Smart Contract\n\`\`\`rust\n${contractCode.slice(0, 3000)}\n\`\`\`` : '',
    '\n\n> ⚠️ **Política de Aprovação:** O merge automático está desativado. Este Pull Request requer revisão e merge manual diretamente no GitHub.',
  ].join('');

  // 4. Create Pull Request using real GitHub API
  const ghResponse = await fetch(`https://api.github.com/repos/${targetOwner}/${targetRepo}/pulls`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      title: prTitle,
      head: branch,
      base: 'main',
      body: prDescription,
      draft: false,
    }),
  });

  const ghData = await ghResponse.json().catch(() => ({}));

  if (!ghResponse.ok) {
    const errorMsg = ghData.message || 'Falha ao criar Pull Request na API do GitHub.';
    const detailedErrors = Array.isArray(ghData.errors)
      ? ghData.errors.map((e: any) => e.message || JSON.stringify(e)).join('; ')
      : '';
    throw new Error(`Erro da API do GitHub (${ghResponse.status}): ${errorMsg}${detailedErrors ? ` - Detalhes: ${detailedErrors}` : ''}`);
  }

  if (ghData.state !== 'open') {
    throw new Error(`O GitHub retornou um estado inesperado para o Pull Request: "${ghData.state}". O PR não está "open".`);
  }

  return {
    success: true,
    mode: 'live_github_api',
    prStatus: 'OPEN',
    manualMergeRequired: true,
    autoMergeEnabled: false,
    prUrl: ghData.html_url,
    prNumber: ghData.number,
    owner: targetOwner,
    repo: targetRepo,
    branch,
    message: `Pull Request #${ghData.number} aberto com sucesso e status "Open" em ${targetOwner}/${targetRepo}. Aguardando revisão e merge manual no GitHub.`,
  };
}
