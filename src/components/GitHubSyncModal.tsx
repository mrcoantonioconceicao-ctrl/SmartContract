/**
 * GitHub Sync, Fork & Pull Request Dispatch Modal
 * Component: src/components/GitHubSyncModal.tsx
 * Strictly enforces Manual-Only Merge Policy: Opens Pull Request with status "OPEN",
 * leaving review and merge execution strictly to manual control in the GitHub repository.
 */

import React, { useState, useEffect } from 'react';
import { 
  GitPullRequest, 
  GitBranch, 
  GitFork, 
  CheckCircle2, 
  AlertCircle, 
  X, 
  ExternalLink, 
  RotateCcw, 
  Lock, 
  Send,
  User,
  FolderGit2,
  ShieldCheck,
  AlertTriangle,
  ShieldAlert,
  Terminal,
  GitCommit,
  Check,
  Settings
} from 'lucide-react';
import { GitHubPipelinePayload } from '../../client/index.ts';
import { runSecurityLintAudit, SecurityLintFinding } from '../services/securityLintingService.ts';

interface GitHubSyncModalProps {
  isOpen: boolean;
  onClose: () => void;
  pipelinePayload: GitHubPipelinePayload;
}

type SyncStep = 'idle' | 'linting' | 'forking' | 'branching' | 'committing' | 'creating_pr' | 'success' | 'error';

const STORAGE_KEY_OWNER = 'github_sync_owner';
const STORAGE_KEY_REPO = 'github_sync_repo';
const STORAGE_KEY_TOKEN = 'github_sync_token';

export function GitHubSyncModal({ isOpen, onClose, pipelinePayload }: GitHubSyncModalProps) {
  // Initialize from localStorage or defaults
  const [owner, setOwner] = useState<string>(() => {
    return localStorage.getItem(STORAGE_KEY_OWNER) || 'mrcoantonioconceicao-ctrl';
  });

  const [repoName, setRepoName] = useState<string>(() => {
    return localStorage.getItem(STORAGE_KEY_REPO) || 'SlipPay2';
  });

  const [token, setToken] = useState<string>(() => {
    return localStorage.getItem(STORAGE_KEY_TOKEN) || '';
  });

  const [branchName, setBranchName] = useState<string>(pipelinePayload.targetBranch);
  const [syncStep, setSyncStep] = useState<SyncStep>('idle');
  const [prUrl, setPrUrl] = useState<string>('');
  const [prNumber, setPrNumber] = useState<number | null>(null);
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [backendMessage, setBackendMessage] = useState<string>('');
  const [lintFindings, setLintFindings] = useState<SecurityLintFinding[]>([]);
  const [lintErrorCount, setLintErrorCount] = useState<number>(0);

  // Git Pre-Commit Hook Management State
  const [hookInstalled, setHookInstalled] = useState<boolean>(true);
  const [hookAuditStrictActive, setHookAuditStrictActive] = useState<boolean>(true);
  const [hookActionLoading, setHookActionLoading] = useState<boolean>(false);
  const [hookFeedbackMessage, setHookFeedbackMessage] = useState<string>('');

  // Fetch hook status on mount
  useEffect(() => {
    let isMounted = true;
    async function checkHookStatus() {
      try {
        const res = await fetch('/api/git-hooks/status');
        const data = await res.json();
        if (isMounted && data.success) {
          setHookInstalled(data.installed);
          setHookAuditStrictActive(data.isAuditStrictActive);
        }
      } catch {
        // Fallback em caso de offline
      }
    }
    checkHookStatus();
    return () => { isMounted = false; };
  }, []);

  const handleToggleHook = async () => {
    setHookActionLoading(true);
    setHookFeedbackMessage('');
    try {
      const endpoint = hookInstalled ? '/api/git-hooks/uninstall' : '/api/git-hooks/install';
      const res = await fetch(endpoint, { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        setHookInstalled(data.installed);
        setHookAuditStrictActive(data.isAuditStrictActive);
        setHookFeedbackMessage(data.message || (data.installed ? 'Pre-commit hook ativado!' : 'Pre-commit hook desativado.'));
      } else {
        setHookFeedbackMessage(data.error || 'Falha ao gerenciar hook.');
      }
    } catch (err: any) {
      setHookFeedbackMessage(err.message || 'Erro ao conectar ao servidor.');
    } finally {
      setHookActionLoading(false);
      setTimeout(() => setHookFeedbackMessage(''), 4000);
    }
  };

  // Sync state if payload branch changes
  useEffect(() => {
    if (pipelinePayload?.targetBranch) {
      setBranchName(pipelinePayload.targetBranch);
    }
  }, [pipelinePayload]);

  // Dynamic Pre-Push Validation: executes runSecurityLintAudit (audit_strict) on payload files
  const [prePushReport, setPrePushReport] = useState(() => {
    const filesToLint = (pipelinePayload?.commit?.files || []).map(f => ({
      path: f.path,
      content: f.content,
    }));
    return runSecurityLintAudit(filesToLint, 'audit_strict');
  });

  useEffect(() => {
    const filesToLint = (pipelinePayload?.commit?.files || []).map(f => ({
      path: f.path,
      content: f.content,
    }));
    const report = runSecurityLintAudit(filesToLint, 'audit_strict');
    setPrePushReport(report);
  }, [pipelinePayload]);

  // Persist to localStorage whenever inputs change
  const handleOwnerChange = (val: string) => {
    setOwner(val);
    localStorage.setItem(STORAGE_KEY_OWNER, val);
  };

  const handleRepoChange = (val: string) => {
    setRepoName(val);
    localStorage.setItem(STORAGE_KEY_REPO, val);
  };

  const handleTokenChange = (val: string) => {
    setToken(val);
    localStorage.setItem(STORAGE_KEY_TOKEN, val);
  };

  if (!isOpen) return null;

  const cleanOwner = owner.trim();
  const cleanRepo = repoName.trim();
  const cleanToken = token.trim();
  const dynamicRepoUrl = `https://github.com/${cleanOwner || 'owner'}/${cleanRepo || 'repo'}`;

  // Validacao de Pre-Push: bloqueia se houver violacoes criticas sob audit_strict
  const hasSecurityViolations = !prePushReport.passed || prePushReport.errorCount > 0;

  const isFormValid = Boolean(
    cleanOwner &&
    cleanRepo &&
    cleanToken &&
    (cleanToken.startsWith('ghp_') || cleanToken.startsWith('github_pat_')) &&
    !hasSecurityViolations
  );

  const handleStartSync = async () => {
    // 1. Mandatory Token Validation
    if (!cleanToken) {
      setErrorMessage('GitHub Personal Access Token (PAT) é OBRIGATÓRIO. Introduza o seu token antes de sincronizar.');
      setSyncStep('error');
      return;
    }

    if (!cleanToken.startsWith('ghp_') && !cleanToken.startsWith('github_pat_')) {
      setErrorMessage('Formato de token inválido. O GitHub PAT deve começar por "ghp_" (Classic) ou "github_pat_" (Fine-grained).');
      setSyncStep('error');
      return;
    }

    if (!cleanOwner) {
      setErrorMessage('Por favor, introduza o utilizador ou organização do GitHub.');
      setSyncStep('error');
      return;
    }

    if (!cleanRepo) {
      setErrorMessage('Por favor, introduza o nome do repositório de destino.');
      setSyncStep('error');
      return;
    }

    localStorage.setItem(STORAGE_KEY_OWNER, cleanOwner);
    localStorage.setItem(STORAGE_KEY_REPO, cleanRepo);
    localStorage.setItem(STORAGE_KEY_TOKEN, cleanToken);

    setErrorMessage('');
    setPrUrl('');
    setPrNumber(null);
    setLintFindings([]);
    setLintErrorCount(0);

    // 2. Validador de Integridade Pre-Flight (Perfil 'audit_strict'):
    // Executa analise estrita antes da criacao do PR para garantir que nenhum codigo com
    // panic!(), .unwrap(), .expect() ou operacoes aritmeticas sem checked_add chegue a branch main.
    setSyncStep('linting');

    const filesToLint = (pipelinePayload?.commit?.files || []).map(f => ({
      path: f.path,
      content: f.content,
    }));

    const lintReport = runSecurityLintAudit(filesToLint, 'audit_strict');

    // Filtrar especificamente violacoes de panic e falta de checked_add
    const criticalViolations = lintReport.findings.filter(f => 
      f.ruleId === 'clippy::panic' || 
      f.ruleId === 'clippy::unwrap_used' || 
      f.ruleId === 'clippy::expect_used' || 
      f.ruleId === 'clippy::integer_arithmetic' ||
      f.severity === 'error'
    );

    if (criticalViolations.length > 0) {
      setLintFindings(criticalViolations);
      setLintErrorCount(criticalViolations.length);
      setErrorMessage(
        `Pre-verificacao de seguranca (audit_strict) FALHOU: ${criticalViolations.length} violacao(oes) critica(s) detetada(s). ` +
        `E estritamente proibido abrir PR com instrucoes contendo panic!() ou operacoes aritmeticas sem checked_add(). ` +
        `Corrija os arquivos para assegurar a integridade da branch main.`
      );
      setSyncStep('error');
      return;
    }

    setSyncStep('forking');

    try {
      setSyncStep('committing');

      // Dispatch to production backend with real GitHub API execution
      const res = await fetch('/api/github/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: cleanToken,
          owner: cleanOwner,
          repoName: cleanRepo,
          branchName: branchName.trim(),
          payload: {
            ...pipelinePayload,
            repository: `${cleanOwner}/${cleanRepo}`,
          },
        }),
      });

      const data = await res.json().catch(() => ({ success: false, error: 'Resposta inválida do servidor' }));

      if (!res.ok || !data.success) {
        throw new Error(data.error || `Erro HTTP ${res.status}: Falha ao contactar a API do GitHub`);
      }

      // Verify that the PR was actually created and is live with status OPEN
      if (!data.prUrl || data.prStatus !== 'OPEN') {
        throw new Error('A API do GitHub não confirmou a abertura do Pull Request com o status "Open".');
      }

      setPrUrl(data.prUrl);
      setPrNumber(data.prNumber || null);
      setBackendMessage(data.message || 'Pull Request aberto com status "Open" no GitHub.');
      setSyncStep('success');
    } catch (err: any) {
      setSyncStep('error');
      setErrorMessage(err.message || 'Erro inesperado durante a comunicação com a API do GitHub');
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-3 sm:p-4 animate-in fade-in duration-200">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-xl w-full max-h-[92vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/80">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-emerald-950/60 border border-emerald-800/40 text-emerald-400">
              <GitPullRequest className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-white">Criar & Abrir Pull Request no GitHub</h3>
              <p className="text-[11px] text-slate-400">Status "Open" • Revisão e Merge Estritamente Manual</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors min-h-[36px] min-w-[36px] flex items-center justify-center"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Content */}
        <div className="p-5 overflow-y-auto space-y-4 text-xs font-mono touch-scroll">
          {syncStep === 'idle' && (
            <>
              {/* Dynamic Target Preview Bar */}
              <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-[11px]">
                <span className="text-slate-400 flex items-center gap-1.5">
                  <FolderGit2 className="w-3.5 h-3.5 text-cyan-400" />
                  Destino Dinâmico:
                </span>
                <span className="text-cyan-300 font-bold truncate max-w-[260px]">
                  {cleanOwner}/{cleanRepo}
                </span>
              </div>

              {/* Strict Manual Merge Notice & Integrity Shield */}
              <div className="p-3 rounded-lg bg-purple-950/20 border border-purple-800/40 flex items-start gap-2.5 text-slate-300 text-[11px] leading-relaxed">
                <ShieldCheck className="w-4 h-4 text-purple-400 shrink-0 mt-0.5" />
                <div>
                  <strong className="text-purple-300 font-semibold">Política de Merge Manual:</strong>
                  <div>O sistema apenas cria o commit e abre o Pull Request com status <strong className="text-emerald-400">"Open"</strong>. Merge automatico 100% desativado.</div>
                </div>
              </div>

              {/* Componente de Validacao de Pre-Push (Perfil audit_strict) */}
              <div className={`p-3.5 rounded-xl border transition-all ${
                hasSecurityViolations
                  ? 'bg-rose-950/30 border-rose-800/60 shadow-lg shadow-rose-950/20'
                  : 'bg-emerald-950/20 border-emerald-800/40'
              }`}>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    {hasSecurityViolations ? (
                      <ShieldAlert className="w-4 h-4 text-rose-400" />
                    ) : (
                      <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    )}
                    <span className="text-xs font-bold text-white">
                      Validacao de Pre-Push: Perfil audit_strict
                    </span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wide uppercase ${
                    hasSecurityViolations
                      ? 'bg-rose-900/60 text-rose-300 border border-rose-700/60'
                      : 'bg-emerald-900/60 text-emerald-300 border border-emerald-700/60'
                  }`}>
                    {hasSecurityViolations ? `${prePushReport.errorCount} VIOLACAO(OES)` : 'APROVADO (ZERO-PANIC)'}
                  </span>
                </div>

                <p className="text-[11px] text-slate-300 leading-relaxed">
                  {hasSecurityViolations
                    ? 'Submissao bloqueada. Existem violacoes criticas de seguranca (panic, unwrap ou falta de checked_add) no codigo a ser enviado.'
                    : 'Codigo verificado com sucesso. Zero panicos na SVM, aritmetica segura com checked_add/checked_sub e privilegios de signatario auditados.'}
                </p>

                {/* Exibicao dos erros detalhados para o desenvolvedor antes da submissao */}
                {hasSecurityViolations && (
                  <div className="mt-3 space-y-2 border-t border-rose-900/40 pt-2.5">
                    <div className="text-[10px] font-bold text-rose-400 flex items-center gap-1">
                      <AlertCircle className="w-3 h-3" />
                      <span>Erros que bloqueiam a criacao do PR:</span>
                    </div>
                    <div className="max-h-36 overflow-y-auto space-y-1.5 pr-1">
                      {prePushReport.findings.filter(f => f.severity === 'error').map((finding) => (
                        <div key={finding.id} className="p-2 rounded bg-slate-950/80 border border-rose-800/50 text-[10px] font-mono">
                          <div className="text-rose-300 font-bold">[{finding.ruleId}] {finding.file}:{finding.line}</div>
                          <div className="text-slate-300 mt-0.5">{finding.message}</div>
                          {finding.snippet && (
                            <code className="text-amber-300 bg-slate-900 px-1 py-0.5 rounded mt-1 block truncate">
                              {finding.snippet}
                            </code>
                          )}
                          <div className="text-emerald-400 mt-1">Solucao: {finding.remediation}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Componente: Gerenciador de Git Pre-Commit Hooks (Automacao Local) */}
              <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2.5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className={`p-1.5 rounded-lg ${hookInstalled ? 'bg-emerald-950 border border-emerald-800/60 text-emerald-400' : 'bg-slate-800 text-slate-400'}`}>
                      <GitCommit className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="text-xs font-bold text-white flex items-center gap-2">
                        <span>Git Pre-Commit Hook Manager</span>
                        <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${
                          hookInstalled
                            ? 'bg-emerald-900/60 text-emerald-300 border border-emerald-700/50'
                            : 'bg-slate-800 text-slate-400'
                        }`}>
                          {hookInstalled ? 'HOOK ATIVO (.git/hooks)' : 'DESATIVADO'}
                        </span>
                      </div>
                      <p className="text-[10px] text-slate-400 mt-0.5">
                        Executa o <code className="text-purple-300">securityLintingService.ts</code> (audit_strict) antes de cada commit local.
                      </p>
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={handleToggleHook}
                    disabled={hookActionLoading}
                    className={`px-3 py-1.5 rounded-lg text-[11px] font-semibold flex items-center gap-1.5 transition-all ${
                      hookInstalled
                        ? 'bg-rose-950/60 hover:bg-rose-900/60 text-rose-300 border border-rose-800/60'
                        : 'bg-emerald-950/80 hover:bg-emerald-900/80 text-emerald-300 border border-emerald-700/60 shadow-lg shadow-emerald-950/30'
                    }`}
                  >
                    {hookActionLoading ? (
                      <RotateCcw className="w-3 h-3 animate-spin" />
                    ) : hookInstalled ? (
                      <X className="w-3 h-3" />
                    ) : (
                      <Check className="w-3 h-3" />
                    )}
                    <span>{hookInstalled ? 'Desativar Hook' : 'Instalar Hook'}</span>
                  </button>
                </div>

                {hookFeedbackMessage && (
                  <div className="p-2 rounded bg-slate-900 border border-slate-700 text-[10px] text-cyan-300 font-mono flex items-center gap-1.5">
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span>{hookFeedbackMessage}</span>
                  </div>
                )}

                <div className="p-2 rounded bg-slate-900/60 border border-slate-800/80 text-[10px] text-slate-400 flex items-start gap-2">
                  <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                  <div className="leading-relaxed">
                    <strong>Garantia de Bloqueio em Stage:</strong> Com o hook instalado, nenhum desenvolvedor consegue executar <code className="text-cyan-300">git commit</code> se houver <code className="text-rose-300">panic!()</code>, <code className="text-rose-300">.unwrap()</code> ou operacoes sem <code className="text-emerald-300">checked_add()</code> no codigo Rust/Solana.
                  </div>
                </div>
              </div>

              {/* 1. GitHub Username / Organization Input */}
              <div>
                <label className="text-slate-300 text-[11px] font-semibold flex items-center gap-1.5 mb-1">
                  <User className="w-3.5 h-3.5 text-purple-400" />
                  <span>Utilizador / Organização do GitHub:</span>
                </label>
                <input
                  type="text"
                  placeholder="Ex: mrcoantonioconceicao-ctrl"
                  value={owner}
                  onChange={(e) => handleOwnerChange(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-purple-300 focus:outline-none focus:border-purple-500 transition-colors"
                />
                <span className="text-[10px] text-slate-500 mt-0.5 block">
                  Gravado no <code className="text-slate-400">localStorage</code>
                </span>
              </div>

              {/* 2. Repository Name Input */}
              <div>
                <label className="text-slate-300 text-[11px] font-semibold flex items-center gap-1.5 mb-1">
                  <FolderGit2 className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Nome do Repositório de Destino:</span>
                </label>
                <input
                  type="text"
                  placeholder="Ex: SlipPay2 ou contratos-inteligentes"
                  value={repoName}
                  onChange={(e) => handleRepoChange(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-cyan-300 focus:outline-none focus:border-cyan-500 transition-colors"
                />
                <span className="text-[10px] text-slate-500 mt-0.5 block">
                  Gravado no <code className="text-slate-400">localStorage</code>
                </span>
              </div>

              {/* Branch Name Input */}
              <div>
                <label className="text-slate-300 text-[11px] font-semibold flex items-center gap-1.5 mb-1">
                  <GitBranch className="w-3.5 h-3.5 text-amber-400" />
                  <span>Branch Atómica:</span>
                </label>
                <input
                  type="text"
                  value={branchName}
                  onChange={(e) => setBranchName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-amber-300 focus:outline-none focus:border-amber-500 transition-colors"
                />
              </div>

              {/* Personal Access Token Input (MANDATORY) */}
              <div>
                <div className="flex justify-between items-center mb-1">
                  <label className="text-slate-300 text-[11px] font-semibold flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-rose-400" />
                    <span>GitHub Personal Access Token:</span>
                    <span className="text-[10px] text-rose-400 font-bold tracking-wider uppercase ml-1">(Obrigatório)</span>
                  </label>
                  <span className="text-[10px] text-slate-400">Permissões de repo / PR</span>
                </div>
                <input
                  type="password"
                  placeholder="ghp_xxxxxxxxxxxx ou github_pat_xxxxxxxxxxxx"
                  value={token}
                  onChange={(e) => handleTokenChange(e.target.value)}
                  className={`w-full bg-slate-950 border ${!cleanToken ? 'border-rose-900/60 focus:border-rose-500' : 'border-slate-800 focus:border-purple-500'} rounded-lg px-3 py-2 text-slate-300 focus:outline-none transition-colors`}
                  required
                />
                {!cleanToken && (
                  <p className="text-[10px] text-rose-400/90 mt-1 flex items-center gap-1">
                    <AlertCircle className="w-3 h-3 shrink-0" />
                    <span>Obrigatório para autenticação real e abertura de PR no GitHub.</span>
                  </p>
                )}
              </div>
            </>
          )}

          {/* Linting Progress Display */}
          {syncStep === 'linting' && (
            <div className="py-8 flex flex-col items-center justify-center space-y-4">
              <ShieldAlert className="w-8 h-8 text-amber-400 animate-pulse" />
              <div className="text-center">
                <div className="text-sm font-bold text-white">
                  A executar Validador de Integridade (Perfil audit_strict)...
                </div>
                <p className="text-[11px] text-slate-400 mt-1 font-mono">
                  Inspecionando AST contra panic!(), .unwrap() e ausencia de checked_add()...
                </p>
                <p className="text-[10px] text-amber-400 mt-2 font-mono">
                  Garantia de que nenhum codigo inseguro atinja o branch main
                </p>
              </div>
            </div>
          )}

          {/* Syncing Progress Display */}
          {(syncStep === 'committing' || syncStep === 'creating_pr' || syncStep === 'forking') && (
            <div className="py-8 flex flex-col items-center justify-center space-y-4">
              <RotateCcw className="w-8 h-8 text-cyan-400 animate-spin" />
              <div className="text-center">
                <div className="text-sm font-bold text-white">
                  A autenticar com a API do GitHub e a criar Pull Request para {cleanOwner}/{cleanRepo}...
                </div>
                <p className="text-[11px] text-slate-400 mt-1 font-mono">{dynamicRepoUrl}</p>
                <p className="text-[10px] text-cyan-400 mt-2 font-mono">Conexão direta e segura com a API do GitHub</p>
              </div>
            </div>
          )}

          {/* Success State */}
          {syncStep === 'success' && (
            <div className="py-3 space-y-4">
              <div className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-500/40 flex items-start gap-3">
                <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <div className="flex items-center gap-2">
                    <h4 className="text-sm font-bold text-emerald-300">
                      Pull Request {prNumber ? `#${prNumber} ` : ''}Aberto no GitHub!
                    </h4>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-900/60 text-emerald-300 border border-emerald-500/40">
                      STATUS: OPEN
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                    {backendMessage || 'O Pull Request foi criado e permanece com o status "Open" no GitHub.'}
                  </p>
                </div>
              </div>

              {/* Explicit Manual Approval Callout */}
              <div className="p-3 rounded-lg bg-amber-950/20 border border-amber-800/40 flex items-start gap-2.5 text-xs text-amber-200">
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div className="leading-relaxed text-[11px]">
                  <strong>Controlo Manual Exclusivo:</strong> O merge automático NÃO é executado. A aprovação das mudanças e o merge final devem ser realizados manualmente por si ou pela equipa no repositório.
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1.5 text-xs">
                <div className="flex justify-between text-slate-400">
                  <span>Repositório:</span>
                  <span className="text-cyan-300">{cleanOwner}/{cleanRepo}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Branch:</span>
                  <span className="text-purple-300">{branchName}</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Status do PR:</span>
                  <span className="text-emerald-400 font-bold">Open (Aguardando Revisão)</span>
                </div>
                {prNumber && (
                  <div className="flex justify-between text-slate-400">
                    <span>Número do PR:</span>
                    <span className="text-white font-semibold">#{prNumber}</span>
                  </div>
                )}
                <div className="flex justify-between text-slate-400">
                  <span>API GitHub:</span>
                  <span className="text-emerald-400">Confirmado em Tempo Real</span>
                </div>
              </div>

              <a
                href={prUrl}
                target="_blank"
                rel="noreferrer"
                className="w-full py-2.5 px-4 rounded-lg bg-gradient-to-r from-emerald-600 via-teal-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 text-white font-semibold text-xs flex items-center justify-center gap-2 shadow-lg shadow-emerald-600/30 transition-all"
              >
                <span>Rever e Efetuar Merge Manualmente no GitHub</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </a>
            </div>
          )}

          {/* Error State */}
          {syncStep === 'error' && (
            <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/50 space-y-3">
              <div className="flex items-center gap-2 text-rose-400 font-bold">
                <AlertCircle className="w-4 h-4" />
                <span>Bloqueio de Seguranca / Falha na Abertura do PR</span>
              </div>
              <p className="text-xs text-rose-300">{errorMessage}</p>

              {/* Detalhes de violacoes de linting estrito se houver */}
              {lintFindings.length > 0 && (
                <div className="space-y-2 mt-2">
                  <div className="text-[11px] font-bold text-rose-400 flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5" />
                    <span>Violacoes Detetadas no Perfil audit_strict ({lintErrorCount}):</span>
                  </div>
                  <div className="max-h-40 overflow-y-auto space-y-1.5 pr-1">
                    {lintFindings.map((finding) => (
                      <div key={finding.id} className="p-2 rounded bg-slate-950 border border-rose-900/60 text-[10px] font-mono">
                        <div className="text-rose-400 font-bold">[{finding.ruleId}] {finding.file}:{finding.line}</div>
                        <div className="text-slate-300 mt-0.5">{finding.message}</div>
                        {finding.snippet && (
                          <code className="text-amber-300 bg-slate-900 px-1 py-0.5 rounded mt-1 block truncate">
                            {finding.snippet}
                          </code>
                        )}
                        <div className="text-emerald-400 mt-1">Correcao: {finding.remediation}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="text-[11px] text-slate-400">
                Verifique se o codigo esta em conformidade com as regras de zero-panic e operacoes com checked_add().
              </div>
              <button
                onClick={() => setSyncStep('idle')}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded text-xs transition-colors"
              >
                Revisar e Tentar Novamente
              </button>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        {syncStep === 'idle' && (
          <div className="px-5 py-3.5 bg-slate-950/80 border-t border-slate-800 flex justify-between items-center">
            <span className="text-[10px] text-slate-500">
              Merge manual estritamente obrigatório
            </span>
            <div className="flex gap-2">
              <button
                onClick={onClose}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs transition-colors"
              >
                Cancelar
              </button>
              <button
                onClick={handleStartSync}
                disabled={!isFormValid}
                className={`px-4 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all ${
                  isFormValid
                    ? 'bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white shadow-lg shadow-purple-600/30 active:scale-95 cursor-pointer'
                    : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700/50'
                }`}
                title={
                  hasSecurityViolations
                    ? `Bloqueado por Seguranca: ${prePushReport.errorCount} violacao(oes) no perfil audit_strict`
                    : !cleanToken
                    ? 'GitHub Personal Access Token e OBRIGATORIO'
                    : !cleanOwner || !cleanRepo
                    ? 'Preencha utilizador e repositorio de destino'
                    : 'Abrir Pull Request real no GitHub'
                }
              >
                <Send className="w-3.5 h-3.5" />
                <span>
                  {hasSecurityViolations
                    ? 'Submissao Bloqueada (Violações audit_strict)'
                    : `Abrir Pull Request (Status Open) em ${cleanRepo || 'Repositório'}`}
                </span>
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
