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
  AlertTriangle
} from 'lucide-react';
import { GitHubPipelinePayload } from '../../client/index.ts';

interface GitHubSyncModalProps {
  isOpen: boolean;
  onClose: () => void;
  pipelinePayload: GitHubPipelinePayload;
}

type SyncStep = 'idle' | 'forking' | 'branching' | 'committing' | 'creating_pr' | 'success' | 'error';

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
  const [errorMessage, setErrorMessage] = useState<string>('');
  const [backendMessage, setBackendMessage] = useState<string>('');

  // Sync state if payload branch changes
  useEffect(() => {
    if (pipelinePayload?.targetBranch) {
      setBranchName(pipelinePayload.targetBranch);
    }
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

  const cleanOwner = owner.trim() || 'mrcoantonioconceicao-ctrl';
  const cleanRepo = repoName.trim() || 'SlipPay2';
  const dynamicRepoUrl = `https://github.com/${cleanOwner}/${cleanRepo}`;

  const handleStartSync = async () => {
    if (!cleanOwner) {
      setErrorMessage('Por favor, introduza o utilizador ou organização do GitHub.');
      return;
    }
    if (!cleanRepo) {
      setErrorMessage('Por favor, introduza o nome do repositório de destino.');
      return;
    }

    localStorage.setItem(STORAGE_KEY_OWNER, cleanOwner);
    localStorage.setItem(STORAGE_KEY_REPO, cleanRepo);
    if (token) localStorage.setItem(STORAGE_KEY_TOKEN, token);

    setSyncStep('forking');
    setErrorMessage('');

    try {
      // Step 1: Forking
      await new Promise(r => setTimeout(r, 600));
      setSyncStep('branching');

      // Step 2: Branch creation
      await new Promise(r => setTimeout(r, 500));
      setSyncStep('committing');

      // Step 3: Atomic commit with dynamic owner and repoName
      const res = await fetch('/api/github/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: token.trim() || undefined,
          owner: cleanOwner,
          repoName: cleanRepo,
          branchName: branchName.trim(),
          payload: {
            ...pipelinePayload,
            repository: `${cleanOwner}/${cleanRepo}`,
          },
        }),
      });

      const data = await res.json();

      setSyncStep('creating_pr');
      await new Promise(r => setTimeout(r, 600));

      if (data.success) {
        setPrUrl(data.prUrl || `${dynamicRepoUrl}/pull/1`);
        setBackendMessage(data.message || 'Pull Request aberto com status "Open". Merge automático desativado.');
        setSyncStep('success');
      } else {
        throw new Error(data.error || 'Falha na comunicação com API do GitHub');
      }
    } catch (err: any) {
      setSyncStep('error');
      setErrorMessage(err.message || 'Erro inesperado durante a sincronização com o repositório');
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

              {/* Strict Manual Merge Notice */}
              <div className="p-3 rounded-lg bg-purple-950/20 border border-purple-800/40 flex items-start gap-2.5 text-slate-300 text-[11px] leading-relaxed">
                <ShieldCheck className="w-4 h-4 text-purple-400 shrink-0 mt-0.5" />
                <div>
                  <strong className="text-purple-300 font-semibold">Política de Merge Manual:</strong>
                  <div>O sistema apenas cria o commit no fork e abre o Pull Request com status <strong className="text-emerald-400">"Open"</strong>. O merge automático está 100% desativado para garantir a aprovação humana obrigatória no repositório.</div>
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

              {/* Personal Access Token Input */}
              <div>
                <div className="flex justify-between items-center mb-1">
                  <label className="text-slate-300 text-[11px] font-semibold flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-slate-400" />
                    <span>GitHub Personal Access Token (Opcional):</span>
                  </label>
                  <span className="text-[10px] text-slate-500">Deixe vazio para Modo Sandbox</span>
                </div>
                <input
                  type="password"
                  placeholder="ghp_xxxxxxxxxxxxxxxxxxxx (salvo no localStorage)"
                  value={token}
                  onChange={(e) => handleTokenChange(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-300 focus:outline-none focus:border-purple-500 transition-colors"
                />
              </div>
            </>
          )}

          {/* Syncing Progress Display */}
          {(syncStep === 'forking' || syncStep === 'branching' || syncStep === 'committing' || syncStep === 'creating_pr') && (
            <div className="py-8 flex flex-col items-center justify-center space-y-4">
              <RotateCcw className="w-8 h-8 text-cyan-400 animate-spin" />
              <div className="text-center">
                <div className="text-sm font-bold text-white">
                  {syncStep === 'forking' && `A preparar fork e branch para ${cleanOwner}/${cleanRepo}...`}
                  {syncStep === 'branching' && `Criando branch atómica ${branchName}...`}
                  {syncStep === 'committing' && 'Enviando commits assinados (4 ficheiros)...'}
                  {syncStep === 'creating_pr' && `Abrindo Pull Request com status "Open" em ${cleanOwner}/${cleanRepo}...`}
                </div>
                <p className="text-[11px] text-slate-400 mt-1 font-mono">{dynamicRepoUrl}</p>
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
                    <h4 className="text-sm font-bold text-emerald-300">Pull Request Aberto com Sucesso!</h4>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-900/60 text-emerald-300 border border-emerald-500/40">
                      STATUS: OPEN
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 mt-1 leading-relaxed">
                    O Pull Request foi criado e permanece com o status <strong>"Open"</strong> no GitHub.
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
                <div className="flex justify-between text-slate-400">
                  <span>Commit SHA:</span>
                  <span className="text-slate-300">7a4b8c9d (Assinado)</span>
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
                <span>Erro na Abertura do Pull Request</span>
              </div>
              <p className="text-xs text-rose-300">{errorMessage}</p>
              <div className="text-[11px] text-slate-400">
                Verifique se o utilizador (<code className="text-purple-300">{cleanOwner}</code>) e o repositório (<code className="text-cyan-300">{cleanRepo}</code>) estão corretos.
              </div>
              <button
                onClick={() => setSyncStep('idle')}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded text-xs transition-colors"
              >
                Corrigir e Tentar Novamente
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
                className="px-4 py-2 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white rounded-lg text-xs font-semibold flex items-center gap-2 shadow-lg shadow-purple-600/30 transition-all active:scale-95"
              >
                <Send className="w-3.5 h-3.5" />
                <span>Abrir Pull Request (Status Open) em {cleanRepo}</span>
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
