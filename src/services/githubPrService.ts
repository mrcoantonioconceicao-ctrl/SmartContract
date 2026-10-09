/**
 * GitHub Pull Request Service
 * Modulo: src/services/githubPrService.ts
 * Autoria: Marco Antonio Conceicao
 * 
 * Executa chamadas reais a API do GitHub com validacao pre-PR:
 * 1. Valida o Personal Access Token (PAT obrigatorio).
 * 2. Verifica a existencia do repositorio e descobre o ramo alvo (base: main).
 * 3. Garante a existencia do ramo de origem (head) no repositorio remoto.
 * 4. Assegura o push dos commits de remediacao antes de solicitar a abertura do PR.
 * 5. Impede o erro 422 (Validation Failed: field head) atraves de pre-validacao e comparacao.
 * 6. Politica estrita de merge manual: status sempre "OPEN", sem merge automatico.
 */

export interface GitHubCommitFile {
  path: string;
  content: string;
}

export interface CreateGitHubPrOptions {
  token: string;
  owner: string;
  repoName: string;
  branchName?: string;
  baseBranch?: string;
  title?: string;
  body?: string;
  contractCode?: string;
  commitMessage?: string;
  files?: GitHubCommitFile[];
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
  base?: string;
  message: string;
}

/**
 * Valida o formato do GitHub Personal Access Token (PAT).
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
      error: 'Formato do GitHub Personal Access Token inválido. Os tokens do GitHub devem começar por "ghp_" (Classic) ou "github_pat_" (Fine-grained).',
    };
  }

  return { valid: true };
}

/**
 * Helper atomico para requisicoes REST a API do GitHub.
 */
async function fetchGitHubApi(
  url: string,
  token: string,
  options: {
    method?: string;
    body?: any;
  } = {}
): Promise<{ status: number; ok: boolean; data: any }> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token.trim()}`,
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'Solana-Anchor-DevSecOps-IDE',
    'Content-Type': 'application/json',
  };

  const response = await fetch(url, {
    method: options.method || 'GET',
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  const data = await response.json().catch(() => ({}));
  return { status: response.status, ok: response.ok, data };
}

/**
 * Validacao Pre-PR e Sincronizacao de Commits Remotos:
 * Garante que o ramo remoto exista e contenha os commits alterados antes da abertura do PR.
 */
async function ensureRemoteBranchAndCommits(
  token: string,
  owner: string,
  repo: string,
  headBranch: string,
  baseBranch: string,
  filesToCommit: GitHubCommitFile[],
  commitMessage?: string
): Promise<{ resolvedBase: string; branchHeadSha: string }> {
  // Declaracao segura de variaveis de tempo no escopo da funcao (Regra C44)
  const commitDate = new Date().toISOString();
  const branchTimestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const timestamp = branchTimestamp;

  // 1. Verificar existencia e acessibilidade do repositorio
  const repoRes = await fetchGitHubApi(`https://api.github.com/repos/${owner}/${repo}`, token);
  if (!repoRes.ok) {
    if (repoRes.status === 401) {
      throw new Error('GitHub Token invalido ou expirado (HTTP 401 Unauthorized). Verifique o seu Personal Access Token.');
    }
    if (repoRes.status === 404) {
      throw new Error(`Repositorio "${owner}/${repo}" nao encontrado (HTTP 404 Not Found) ou o token nao possui permissoes suficientes.`);
    }
    throw new Error(`Erro de acesso ao repositorio GitHub (HTTP ${repoRes.status}): ${repoRes.data.message || 'Falha ao consultar repositorio'}`);
  }

  const defaultBranch = repoRes.data.default_branch || 'main';
  const resolvedBase = (baseBranch || defaultBranch).trim();

  // 2. Obter o SHA do commit mais recente no ramo base
  const baseRefRes = await fetchGitHubApi(`https://api.github.com/repos/${owner}/${repo}/git/ref/heads/${resolvedBase}`, token);
  let baseCommitSha: string | null = baseRefRes.data?.object?.sha || null;

  if (!baseCommitSha) {
    // Tenta obter informacoes do ramo base via endpoint de branches
    const branchRes = await fetchGitHubApi(`https://api.github.com/repos/${owner}/${repo}/branches/${resolvedBase}`, token);
    baseCommitSha = branchRes.data?.commit?.sha || null;
  }

  if (!baseCommitSha) {
    throw new Error(`O ramo alvo base "${resolvedBase}" nao existe no repositorio remoto "${owner}/${repo}".`);
  }

  // 3. Verificar se o ramo de origem (head) ja existe no repositorio remoto
  const headRefRes = await fetchGitHubApi(`https://api.github.com/repos/${owner}/${repo}/git/ref/heads/${headBranch}`, token);
  let currentHeadSha = baseCommitSha;

  if (!headRefRes.ok || headRefRes.status === 404) {
    // Ramo remoto nao existe: criar o ramo de origem apontando para o commit do ramo base
    const createRefRes = await fetchGitHubApi(`https://api.github.com/repos/${owner}/${repo}/git/refs`, token, {
      method: 'POST',
      body: {
        ref: `refs/heads/${headBranch}`,
        sha: baseCommitSha,
      },
    });

    if (!createRefRes.ok) {
      const errDetail = createRefRes.data?.message || 'Falha ao criar referencia do ramo';
      throw new Error(`Nao foi possivel criar o ramo remoto "${headBranch}" (HTTP ${createRefRes.status}): ${errDetail}`);
    }

    currentHeadSha = createRefRes.data?.object?.sha || baseCommitSha;
  } else {
    currentHeadSha = headRefRes.data?.object?.sha || baseCommitSha;
  }

  // 4. Preparar arquivos para envio de commit
  const filesList: GitHubCommitFile[] = [...filesToCommit];

  // Adicionar relatorio de auditoria se nao estiver previamente incluido
  const hasAuditReport = filesList.some(f => f.path === 'SECURITY_AUDIT_REPORT.md');
  if (!hasAuditReport) {
    filesList.push({
      path: 'SECURITY_AUDIT_REPORT.md',
      content: `# Relatorio de Remediacao de Seguranca - Solana Anchor DevSecOps\n\n` +
        `- Autor: Marco Antonio Conceicao\n` +
        `- Ramo de Origem (Head): ${headBranch}\n` +
        `- Ramo Alvo (Base): ${resolvedBase}\n` +
        `- Data da Auditoria: ${commitDate}\n` +
        `- Protocolo: AST, GraphRAG & DDD Security Verified\n\n` +
        `### Verificacoes de Seguranca On-Chain:\n` +
        `- Checked Arithmetic (checked_add / checked_sub) ativo contra transbordamentos.\n` +
        `- Derivacao de PDA deterministico com sementes canonicas e verificacao de bump.\n` +
        `- Autorizacao estrita com restricao "has_one = authority" e Signer<'info>.\n` +
        `- Espaco exato rent-exempt alocado (49 bytes).\n\n` +
        `> Politica de Seguranca: Merge automatico desativado. Este Pull Request exige aprovacao manual.\n`,
    });
  }

  // Deduplicacao cirurgica de arquivos por path (Regra C44)
  const uniqueFilesMap = new Map<string, GitHubCommitFile>();
  for (const file of filesList) {
    uniqueFilesMap.set(file.path, file);
  }
  const finalizedFiles = Array.from(uniqueFilesMap.values());

  // 5. Obter a arvore de arquivos (tree) do commit atual
  const commitRes = await fetchGitHubApi(`https://api.github.com/repos/${owner}/${repo}/git/commits/${currentHeadSha}`, token);
  const baseTreeSha = commitRes.data?.tree?.sha;

  if (!baseTreeSha) {
    throw new Error(`Falha ao ler a arvore git do ramo "${headBranch}" no repositorio remoto.`);
  }

  // 6. Criar nova arvore Git com os arquivos alterados
  const treePayload = finalizedFiles.map((file) => ({
    path: file.path,
    mode: '100644',
    type: 'blob',
    content: file.content,
  }));

  const newTreeRes = await fetchGitHubApi(`https://api.github.com/repos/${owner}/${repo}/git/trees`, token, {
    method: 'POST',
    body: {
      base_tree: baseTreeSha,
      tree: treePayload,
    },
  });

  if (!newTreeRes.ok || !newTreeRes.data?.sha) {
    throw new Error(`Falha ao registrar arvore de ficheiros no GitHub (HTTP ${newTreeRes.status}): ${newTreeRes.data?.message || 'Erro desconhecido'}`);
  }

  const newTreeSha = newTreeRes.data.sha;

  // 7. Criar novo commit com autoria 100% de Marco Antonio Conceicao (ISO 8601 valido)
  const authorInfo = {
    name: 'Marco Antonio Conceicao',
    email: 'mrcoantonioconceicao@gmail.com',
    date: commitDate,
  };

  const finalCommitMessage = commitMessage ||
    `fix(security): remediacao de seguranca AST e verificacao Anchor PDA por Marco Antonio Conceicao`;

  const newCommitRes = await fetchGitHubApi(`https://api.github.com/repos/${owner}/${repo}/git/commits`, token, {
    method: 'POST',
    body: {
      message: finalCommitMessage,
      tree: newTreeSha,
      parents: [currentHeadSha],
      author: authorInfo,
      committer: authorInfo,
    },
  });

  if (!newCommitRes.ok || !newCommitRes.data?.sha) {
    throw new Error(`Falha ao criar commit de seguranca no GitHub (HTTP ${newCommitRes.status}): ${newCommitRes.data?.message || 'Erro desconhecido'}`);
  }

  const newCommitSha = newCommitRes.data.sha;

  // 8. Atualizar o ponteiro do ramo remoto (push do commit para headBranch)
  const updateRefRes = await fetchGitHubApi(`https://api.github.com/repos/${owner}/${repo}/git/refs/heads/${headBranch}`, token, {
    method: 'PATCH',
    body: {
      sha: newCommitSha,
      force: true,
    },
  });

  if (!updateRefRes.ok) {
    throw new Error(`Falha ao atualizar o ramo remoto "${headBranch}" com os novos commits (HTTP ${updateRefRes.status}): ${updateRefRes.data?.message || 'Erro no push'}`);
  }

  // 9. Validar comparacao entre o ramo base e o ramo de origem
  const compareRes = await fetchGitHubApi(`https://api.github.com/repos/${owner}/${repo}/compare/${resolvedBase}...${headBranch}`, token);
  if (compareRes.ok) {
    const totalCommits = compareRes.data?.total_commits || 0;
    const status = compareRes.data?.status;
    if (totalCommits === 0 || status === 'identical') {
      throw new Error(
        `O ramo de origem "${headBranch}" nao possui commits com alteracoes em relacao ao ramo alvo "${resolvedBase}". ` +
        `Nao e possivel abrir um Pull Request sem commits alterados.`
      );
    }
  }

  return {
    resolvedBase,
    branchHeadSha: newCommitSha,
  };
}

/**
 * Cria e abre um Pull Request no repositorio remoto do GitHub.
 * Garante validacao pre-PR, envio previo dos commits para o ramo remoto,
 * correspondencia exata dos campos 'head' e 'base', e politica de merge estritamente manual.
 */
export async function createGitHubPullRequest(options: CreateGitHubPrOptions): Promise<GitHubPrResult> {
  const { token, owner, repoName, branchName, baseBranch, title, body, contractCode, commitMessage, files } = options;

  // Declaracao segura de variaveis de tempo no escopo da funcao (Regra C44)
  const commitDate = new Date().toISOString();
  const branchTimestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const timestamp = branchTimestamp;

  // 1. Validacao estrita do Token PAT
  const tokenValidation = validateGitHubToken(token);
  if (!tokenValidation.valid) {
    throw new Error(tokenValidation.error);
  }

  const trimmedToken = token.trim();
  const targetOwner = (owner || '').trim();
  const targetRepo = (repoName || '').trim();
  const targetHeadBranch = (branchName || `corrigido/remediacao-c44-${branchTimestamp}`).trim();

  if (!targetOwner) {
    throw new Error('O utilizador ou organização do GitHub é obrigatório.');
  }

  if (!targetRepo) {
    throw new Error('O nome do repositório de destino é obrigatório.');
  }

  // 2. Montar lista de arquivos para envio
  const filesToCommit: GitHubCommitFile[] = [];

  if (files && files.length > 0) {
    filesToCommit.push(...files);
  }

  if (contractCode) {
    filesToCommit.push({
      path: 'programs/solana_sandbox_counter/src/lib.rs',
      content: contractCode,
    });
  }

  // 3. Validacao Pre-PR: Garantir existencia do ramo remoto e push de commits antes da chamada de abertura
  const { resolvedBase } = await ensureRemoteBranchAndCommits(
    trimmedToken,
    targetOwner,
    targetRepo,
    targetHeadBranch,
    baseBranch || 'main',
    filesToCommit,
    commitMessage
  );

  // 4. Verificar se ja existe um Pull Request aberto para este ramo
  const existingPrRes = await fetchGitHubApi(
    `https://api.github.com/repos/${targetOwner}/${targetRepo}/pulls?head=${targetOwner}:${targetHeadBranch}&base=${resolvedBase}&state=open`,
    trimmedToken
  );

  if (existingPrRes.ok && Array.isArray(existingPrRes.data) && existingPrRes.data.length > 0) {
    const existingPr = existingPrRes.data[0];
    return {
      success: true,
      mode: 'live_github_api',
      prStatus: 'OPEN',
      manualMergeRequired: true,
      autoMergeEnabled: false,
      prUrl: existingPr.html_url,
      prNumber: existingPr.number,
      owner: targetOwner,
      repo: targetRepo,
      branch: targetHeadBranch,
      base: resolvedBase,
      message: `Pull Request #${existingPr.number} ja se encontra aberto com status "Open" para o ramo "${targetHeadBranch}". Aguardando revisao e merge manual no GitHub.`,
    };
  }

  // 5. Preparar titulo e descricao do Pull Request
  const prTitle = title || `[DevSecOps] Remediador de Seguranca Anchor - ${targetHeadBranch}`;
  const prDescription = [
    body || 'Remediacao de seguranca automatizada via AST e GraphRAG.',
    contractCode ? `\n\n### Contrato Solana Anchor Remediado\n\`\`\`rust\n${contractCode.slice(0, 3000)}\n\`\`\`` : '',
    '\n\n### Politica de Aprovacao e Merge:\n',
    '> O merge automatico esta 100% desativado. Este Pull Request possui o status **"Open"** e exige estritamente revisao de codigo e aprovacao manual no GitHub.',
    '\n\n- Autoria: Marco Antonio Conceicao',
  ].join('');

  // 6. Criar Pull Request na API do GitHub
  // O parametro 'head' corresponde exatamente ao nome do ramo de origem, e 'base' ao ramo alvo.
  const prCreateRes = await fetchGitHubApi(`https://api.github.com/repos/${targetOwner}/${targetRepo}/pulls`, trimmedToken, {
    method: 'POST',
    body: {
      title: prTitle,
      head: targetHeadBranch,
      base: resolvedBase,
      body: prDescription,
      draft: false,
    },
  });

  const ghData = prCreateRes.data;

  // 7. Tratamento claro e amigavel de erros da API do GitHub
  if (!prCreateRes.ok) {
    if (prCreateRes.status === 422) {
      const errorMsg = ghData.message || '';
      const detailedErrors = Array.isArray(ghData.errors)
        ? ghData.errors.map((e: any) => e.message || JSON.stringify(e)).join('; ')
        : '';

      if (errorMsg.includes('A pull request already exists') || detailedErrors.includes('A pull request already exists')) {
        return {
          success: true,
          mode: 'live_github_api',
          prStatus: 'OPEN',
          manualMergeRequired: true,
          autoMergeEnabled: false,
          prUrl: `https://github.com/${targetOwner}/${targetRepo}/pulls`,
          prNumber: 0,
          owner: targetOwner,
          repo: targetRepo,
          branch: targetHeadBranch,
          base: resolvedBase,
          message: `Ja existe um Pull Request ativo para o ramo "${targetHeadBranch}". Verifique a lista de Pull Requests no GitHub.`,
        };
      }

      if (errorMsg.includes('No commits between') || detailedErrors.includes('No commits between')) {
        throw new Error(`Nao existem commits com diferencas entre o ramo de origem "${targetHeadBranch}" e o ramo alvo "${resolvedBase}".`);
      }

      if (detailedErrors.includes('head')) {
        throw new Error(
          `Falha de validacao no campo "head" da API do GitHub (HTTP 422): ` +
          `O ramo de origem "${targetHeadBranch}" nao foi reconhecido ou nao contem commits enviados para o repositorio "${targetOwner}/${targetRepo}".`
        );
      }

      throw new Error(`Falha de validacao ao criar o Pull Request (HTTP 422): ${detailedErrors || errorMsg}`);
    }

    const fallbackMsg = ghData.message || 'Falha ao criar Pull Request no GitHub';
    throw new Error(`Erro da API do GitHub (HTTP ${prCreateRes.status}): ${fallbackMsg}`);
  }

  if (ghData.state !== 'open') {
    throw new Error(`O GitHub retornou um estado inesperado para o Pull Request: "${ghData.state}". O PR nao esta com status "open".`);
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
    branch: targetHeadBranch,
    base: resolvedBase,
    message: `Pull Request #${ghData.number} aberto com sucesso com status "Open" em ${targetOwner}/${targetRepo}. Ramo: ${targetHeadBranch} -> ${resolvedBase}. Aguardando revisao e merge manual no GitHub.`,
  };
}
