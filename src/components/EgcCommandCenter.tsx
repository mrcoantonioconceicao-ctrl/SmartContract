/**
 * Solana Anchor DevSecOps - Centro de Comando EGC
 * Componente: src/components/EgcCommandCenter.tsx
 * Autoria: Marco Antonio Conceicao
 *
 * Plugin e Painel de Comando do Extended Global Context (EGC) conectado
 * estritamente a auditoria estatica/dinamica de smart contracts Solana Anchor,
 * geracao de issues no GitHub e automacao de Pull Requests seguros.
 */

import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  Terminal,
  Cpu,
  GitPullRequest,
  CheckCircle2,
  AlertTriangle,
  AlertCircle,
  FileCode,
  Download,
  ExternalLink,
  Layers,
  Lock,
  Play,
  RotateCcw,
  Zap,
  FolderGit2,
  Check,
  Code2,
  Columns,
  Sparkles,
  Brain
} from 'lucide-react';
import {
  executeEgcOneClickFlow,
  getTargetRepositoryFiles,
  EgcFlowStepStatus,
  EgcOneClickExecutionResult
} from '../services/egcCommandCenterService.ts';
import { runRealRepositoryScan, RealRepoScanResult, RealScanFinding } from '../services/realRepoScanner.ts';
import { generateAuditablePdfReport } from '../services/pdfReportService.ts';
import {
  extractRepositoryArchitectureContext,
  ContextualRepositoryArchitecture
} from '../services/contextualEngine.ts';
import {
  purgeEgcState,
  EGC_CLEAN_CONFIRMATION_MESSAGE
} from '../services/egcStateManager.ts';
import { PreviewRemediationModal } from './PreviewRemediationModal.tsx';
import { AstFinding } from '../utils/astAuditor.ts';
import {
  getLearningState,
  recordPrFeedbackEvent,
  LearningState
} from '../services/continuousLearningEngine.ts';

const STORAGE_KEY_TOKEN = 'github_sync_token';
const STORAGE_KEY_OWNER = 'github_sync_owner';
const STORAGE_KEY_REPO = 'github_sync_repo';

export function EgcCommandCenter() {
  const [token, setToken] = useState<string>(() => localStorage.getItem(STORAGE_KEY_TOKEN) || '');
  const [owner, setOwner] = useState<string>(() => localStorage.getItem(STORAGE_KEY_OWNER) || 'mrcoantonioconceicao-ctrl');
  const [repoName, setRepoName] = useState<string>(() => {
    const stored = localStorage.getItem(STORAGE_KEY_REPO);
    return (stored && stored !== 'SlipPay' && stored !== 'SlipPay2') ? stored : '';
  });
  const [branchName, setBranchName] = useState<string>('corrigido/remediacao-c44');

  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [cleanNotice, setCleanNotice] = useState<string | null>(null);
  const [currentStep, setCurrentStep] = useState<EgcFlowStepStatus | null>(null);
  const [executionResult, setExecutionResult] = useState<EgcOneClickExecutionResult | null>(null);
  const [liveScan, setLiveScan] = useState<RealRepoScanResult | null>(null);
  const [contextArch, setContextArch] = useState<ContextualRepositoryArchitecture | null>(null);
  const [activeTab, setActiveTab] = useState<'context' | 'guarantees' | 'findings' | 'issues' | 'files' | 'learning'>('context');
  const [learningState, setLearningState] = useState<LearningState>(() => getLearningState());
  const [previewFinding, setPreviewFinding] = useState<AstFinding | null>(null);
  const [previewSourceCode, setPreviewSourceCode] = useState<string>('');
  const [isPreviewOpen, setIsPreviewOpen] = useState<boolean>(false);

  // Carrega varredura real inicial dos arquivos do projeto e analise contextual
  useEffect(() => {
    async function loadInitialScan() {
      const files = await getTargetRepositoryFiles();
      const scan = runRealRepositoryScan(files);
      const arch = extractRepositoryArchitectureContext(files);
      setLiveScan(scan);
      setContextArch(arch);
    }
    loadInitialScan();
  }, []);

  const handleTokenChange = (val: string) => {
    setToken(val);
    localStorage.setItem(STORAGE_KEY_TOKEN, val.trim());
  };

  const handleOwnerChange = (val: string) => {
    setOwner(val);
    localStorage.setItem(STORAGE_KEY_OWNER, val.trim());
  };

  const handleRepoChange = (val: string) => {
    setRepoName(val);
    localStorage.setItem(STORAGE_KEY_REPO, val.trim());
  };

  /**
   * Rotina explicita de limpeza de estado (egc clean)
   */
  const handleCleanState = () => {
    const res = purgeEgcState();
    setRepoName('');
    setBranchName('corrigido/remediacao-c44');
    setCleanNotice(res.message);
  };

  /**
   * FLUXO AUTOMATIZADO DE UM CLIQUE:
   * Acionado pelo botao dedicado com o texto exato "Criar Issues".
   */
  const handleCriarIssues = async () => {
    if (isRunning) return;

    if (!repoName.trim()) {
      alert('Por favor, informe o nome do repositorio alvo (ex: Plataforma-nexa) antes de iniciar a auditoria.');
      return;
    }

    setIsRunning(true);
    setCleanNotice(null);
    setExecutionResult(null);

    try {
      const result = await executeEgcOneClickFlow({
        token: token.trim(),
        owner: owner.trim(),
        repoName: repoName.trim(),
        branchName: branchName.trim(),
        onStepProgress: (status) => {
          setCurrentStep(status);
        },
      });

      setExecutionResult(result);
      if (result.scanResult) {
        setLiveScan(result.scanResult);
      }
      if (result.context) {
        setContextArch(result.context);
      }

      // Se o PR foi aberto com sucesso, o auto-purge limpou o estado
      if (result.statePurged || result.prResult?.success) {
        setRepoName('');
        setCleanNotice(EGC_CLEAN_CONFIRMATION_MESSAGE);
      }
    } catch (err: any) {
      setCurrentStep({
        step: 'completed',
        status: 'error',
        message: `Falha geral no fluxo: ${err.message}`,
      });
    } finally {
      setIsRunning(false);
    }
  };

  const handleReDownloadPdf = () => {
    if (!liveScan) return;
    generateAuditablePdfReport({
      scanResult: liveScan,
      issues: executionResult?.issuesResult?.issues || [],
      pullRequest: executionResult?.prResult || null,
      targetRepo: `${owner}/${repoName}`,
      targetBranch: branchName,
    });
  };

  /**
   * Abre o modal de Preview de Remediacao a partir de um achado real
   */
  const handleOpenRemediationPreview = async (f: RealScanFinding) => {
    try {
      const files = await getTargetRepositoryFiles();
      const targetFile = files.find(file => file.path === f.file || file.path.endsWith(f.file));
      const sourceCode = targetFile ? targetFile.content : `// Arquivo: ${f.file}\n${f.snippet || ''}`;

      const astFindingAdapted: AstFinding = {
        id: f.id,
        ruleId: f.ruleId,
        title: f.title,
        severity: f.severity === 'PASS' ? 'PASS' : f.severity === 'CRITICAL' ? 'CRITICAL' : f.severity === 'HIGH' ? 'HIGH' : f.severity === 'MEDIUM' ? 'MEDIUM' : 'LOW',
        line: f.line,
        snippet: f.snippet,
        description: f.description,
        recommendation: f.recommendation,
        autoFixAvailable: !!f.remediationCode,
        fixPatch: f.remediationCode && f.snippet ? {
          search: f.snippet,
          replace: f.remediationCode,
          explanation: `Aplica correcao da AST para ${f.ruleId} em conformidade com as regras Solana/Anchor.`,
        } : undefined,
      };

      setPreviewFinding(astFindingAdapted);
      setPreviewSourceCode(sourceCode);
      setIsPreviewOpen(true);
    } catch {
      // Fallback
      setPreviewFinding({
        id: f.id,
        ruleId: f.ruleId,
        title: f.title,
        severity: f.severity === 'PASS' ? 'PASS' : 'HIGH',
        line: f.line,
        snippet: f.snippet,
        description: f.description,
        recommendation: f.recommendation,
        autoFixAvailable: !!f.remediationCode,
        fixPatch: f.remediationCode && f.snippet ? {
          search: f.snippet,
          replace: f.remediationCode,
          explanation: f.recommendation,
        } : undefined,
      });
      setPreviewSourceCode(f.snippet || '');
      setIsPreviewOpen(true);
    }
  };

  const currentScan = executionResult?.scanResult || liveScan;

  return (
    <div className="space-y-6">
      {/* Top Banner do Centro de Comando EGC */}
      <div className="bg-slate-900 border border-cyan-500/30 rounded-2xl p-6 shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center space-x-2 text-cyan-400 font-mono text-xs font-semibold tracking-wider uppercase mb-1">
              <Cpu className="w-4 h-4" />
              <span>Plugin EGC & Centro de Comando DevSecOps Solana</span>
            </div>
            <h2 className="text-2xl font-bold text-white tracking-tight flex items-center space-x-3">
              <span>Auditoria de Smart Contracts & Automacao Web3</span>
              <span className="bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 text-xs px-2.5 py-0.5 rounded-full font-mono">
                Model Context Protocol
              </span>
            </h2>
            <p className="text-slate-400 text-sm mt-1 max-w-2xl">
              Integracao modular profunda com o barramento do Extended Global Context (EGC).
              Motor de varredura real na arvore fisica do projeto, geracao de issues no GitHub e automacao de Pull Requests sem merge automatico.
            </p>
          </div>

          <div className="flex flex-col items-end">
            <span className="text-xs text-slate-400 font-mono">Autoria:</span>
            <span className="text-sm font-semibold text-cyan-300 font-mono">Marco Antonio Conceicao</span>
            <span className="text-[11px] text-emerald-400 font-mono flex items-center space-x-1 mt-1">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>Regra C44 Ativa (Nao-Destrutiva)</span>
            </span>
          </div>
        </div>
      </div>

      {/* Grid de Garantias On-Chain Solana (Zero Mocks) */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Garantia 1: PDAs Deterministicos */}
        <div className="bg-slate-900/90 border border-slate-800 hover:border-cyan-500/40 rounded-xl p-4 transition-all">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-cyan-400 uppercase font-semibold">1. PDAs Deterministicos</span>
            {currentScan?.solanaGuarantees.deterministicPdas ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            )}
          </div>
          <p className="text-sm font-semibold text-slate-200">Seeds & Canonical Bump</p>
          <p className="text-xs text-slate-400 mt-1">
            Derivacao estrita com seeds [b"counter", authority] e bump armazenado no estado para economizar CUs.
          </p>
        </div>

        {/* Garantia 2: Rent-Exempt 49 Bytes */}
        <div className="bg-slate-900/90 border border-slate-800 hover:border-emerald-500/40 rounded-xl p-4 transition-all">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-emerald-400 uppercase font-semibold">2. Memoria Rent-Exempt</span>
            {currentScan?.solanaGuarantees.rentExemptMemory49B ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            )}
          </div>
          <p className="text-sm font-semibold text-slate-200">Alocacao Exata de 49 Bytes</p>
          <p className="text-xs text-slate-400 mt-1">
            Discriminador (8B) + Authority (32B) + Count (8B) + Bump (1B) com isencao vitalicia de aluguel.
          </p>
        </div>

        {/* Garantia 3: Arithmetic Checked Math */}
        <div className="bg-slate-900/90 border border-slate-800 hover:border-blue-500/40 rounded-xl p-4 transition-all">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-blue-400 uppercase font-semibold">3. Aritmetica Segura</span>
            {currentScan?.solanaGuarantees.checkedArithmetic ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            )}
          </div>
          <p className="text-sm font-semibold text-slate-200">Anti-Overflow / Underflow</p>
          <p className="text-xs text-slate-400 mt-1">
            Enforca .checked_add() e .checked_sub() com reversao de erro customizada contra ataques BPF.
          </p>
        </div>

        {/* Garantia 4: Validacao de Signatarios */}
        <div className="bg-slate-900/90 border border-slate-800 hover:border-purple-500/40 rounded-xl p-4 transition-all">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-purple-400 uppercase font-semibold">4. Signatarios & Posse</span>
            {currentScan?.solanaGuarantees.signerAuthorization ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            )}
          </div>
          <p className="text-sm font-semibold text-slate-200">Signer & has_one = authority</p>
          <p className="text-xs text-slate-400 mt-1">
            Assinaturas Ed25519 verificadas e checagem declarativa has_one para impedir escalacao de privilegios.
          </p>
        </div>
      </div>

      {/* Painel Central: Configuracao GitHub e Botao de Disparo "Criar Issues" */}
      <div className="bg-slate-900/95 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6">
        <div className="border-b border-slate-800 pb-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-bold text-white flex items-center space-x-2">
              <FolderGit2 className="w-5 h-5 text-cyan-400" />
              <span>Parametros de Despacho GitHub & Automacao</span>
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Configure as credenciais e o repositorio alvo para a execucao integrada na API oficial do GitHub.
            </p>
          </div>
          <button
            onClick={handleCleanState}
            title="Limpar cache de variaveis e desvincular alvo anterior (~/.egc/state)"
            className="flex items-center space-x-2 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white px-3 py-1.5 rounded-lg border border-slate-700 text-xs font-mono transition-colors self-start md:self-auto"
          >
            <RotateCcw className="w-3.5 h-3.5 text-cyan-400" />
            <span>Limpar Estado (egc clean)</span>
          </button>
        </div>

        {/* Notificacao visual de limpeza de estado */}
        {cleanNotice && (
          <div className="bg-emerald-950/80 border border-emerald-500/50 rounded-xl p-4 flex items-center justify-between text-emerald-200 text-sm shadow-lg">
            <div className="flex items-center space-x-3">
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
              <div>
                <p className="font-bold text-white font-mono">{cleanNotice}</p>
                <p className="text-xs text-emerald-300/80">
                  Cache de memoria limpo e contexto local desvinculado (~/.egc/state). Forneca o novo repositorio alvo (ex: Plataforma-nexa).
                </p>
              </div>
            </div>
            <button
              onClick={() => setCleanNotice(null)}
              className="text-xs bg-emerald-800/60 hover:bg-emerald-700/60 text-emerald-200 px-2.5 py-1 rounded border border-emerald-600/40 font-mono"
            >
              Fechar
            </button>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* GitHub PAT */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300 flex items-center justify-between">
              <span className="flex items-center space-x-1">
                <Lock className="w-3.5 h-3.5 text-cyan-400" />
                <span>GitHub PAT (Obrigatorio)</span>
              </span>
              <span className="text-[10px] text-cyan-400 font-mono">ghp_...</span>
            </label>
            <input
              type="password"
              value={token}
              onChange={(e) => handleTokenChange(e.target.value)}
              placeholder="ghp_xxxxxxxxxxxx ou github_pat_..."
              className="w-full bg-slate-950 border border-slate-700 focus:border-cyan-500 rounded-lg px-3 py-2 text-xs text-white font-mono focus:outline-none"
            />
          </div>

          {/* Owner */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">Proprietario / Organizacao</label>
            <input
              type="text"
              value={owner}
              onChange={(e) => handleOwnerChange(e.target.value)}
              placeholder="mrcoantonioconceicao-ctrl"
              className="w-full bg-slate-950 border border-slate-700 focus:border-cyan-500 rounded-lg px-3 py-2 text-xs text-white font-mono focus:outline-none"
            />
          </div>

          {/* Repositorio */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">Nome do Repositorio</label>
            <input
              type="text"
              value={repoName}
              onChange={(e) => handleRepoChange(e.target.value)}
              placeholder="ex: Plataforma-nexa ou novo-alvo"
              className="w-full bg-slate-950 border border-slate-700 focus:border-cyan-500 rounded-lg px-3 py-2 text-xs text-white font-mono focus:outline-none"
            />
          </div>

          {/* Branch Alvo */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-slate-300">Ramo Alvo (Origem)</label>
            <input
              type="text"
              value={branchName}
              onChange={(e) => setBranchName(e.target.value)}
              placeholder="corrigido/remediacao-c44"
              className="w-full bg-slate-950 border border-slate-700 focus:border-cyan-500 rounded-lg px-3 py-2 text-xs text-white font-mono focus:outline-none"
            />
          </div>
        </div>

        {/* BOTAO DEDICADO DE UM CLIQUE: TEXTO EXATO "Criar Issues" */}
        <div className="bg-slate-950/80 border border-cyan-500/30 rounded-xl p-5 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="space-y-1 text-center sm:text-left">
            <div className="flex items-center space-x-2 text-cyan-300 text-sm font-bold">
              <Zap className="w-4 h-4 text-cyan-400" />
              <span>Fluxo Automatizado de Um Clique EGC</span>
            </div>
            <p className="text-xs text-slate-400 max-w-xl">
              Ao acionar o botao, o sistema executa a varredura real profunda do repositorio,
              cria e envia as issues reais para a API do GitHub, abre o Pull Request na branch correta (sem erro 422 de head invalido)
              e compila o relatorio PDF auditavel.
            </p>
          </div>

          <button
            onClick={handleCriarIssues}
            disabled={isRunning || !token.trim() || !owner.trim() || !repoName.trim()}
            className={`cursor-pointer px-6 py-3.5 rounded-xl font-bold text-sm tracking-wide transition-all shadow-lg flex items-center space-x-2 whitespace-nowrap ${
              isRunning
                ? 'bg-cyan-700 text-white opacity-80 cursor-wait'
                : !token.trim()
                ? 'bg-slate-800 text-slate-500 border border-slate-700 cursor-not-allowed'
                : 'bg-gradient-to-r from-cyan-500 to-emerald-500 hover:from-cyan-400 hover:to-emerald-400 text-slate-950 font-black shadow-cyan-500/20 hover:shadow-cyan-500/40'
            }`}
          >
            {isRunning ? (
              <>
                <RotateCcw className="w-4 h-4 animate-spin text-white" />
                <span>Processando Varredura & Issues...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-current" />
                <span>Criar Issues</span>
              </>
            )}
          </button>
        </div>

        {/* Stepper de Execucao em Tempo Real */}
        {currentStep && (
          <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-slate-400 font-semibold uppercase tracking-wider">
                Status do Fluxo de Execucao:
              </span>
              <span
                className={`px-2 py-0.5 rounded font-bold ${
                  currentStep.status === 'success'
                    ? 'bg-emerald-500/20 text-emerald-400'
                    : currentStep.status === 'error'
                    ? 'bg-red-500/20 text-red-400'
                    : 'bg-cyan-500/20 text-cyan-400 animate-pulse'
                }`}
              >
                {currentStep.status.toUpperCase()}
              </span>
            </div>
            <p className="text-xs text-slate-200 font-mono bg-slate-900 p-2.5 rounded border border-slate-800">
              {currentStep.message}
            </p>
          </div>
        )}

        {/* Resumo de Sucesso da Execucao */}
        {executionResult && (
          <div className="bg-emerald-950/20 border border-emerald-500/40 rounded-xl p-4 space-y-3">
            <div className="flex items-center space-x-2 text-emerald-400 font-bold text-sm">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              <span>Execucao de Um Clique Concluida com Sucesso!</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2 text-xs font-mono">
              <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block text-[11px]">Issues Criadas no GitHub:</span>
                <span className="text-emerald-300 font-bold text-base">
                  {executionResult.issuesResult.totalCreated} issues reais
                </span>
              </div>

              <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                <span className="text-slate-400 block text-[11px]">Pull Request:</span>
                {executionResult.prResult ? (
                  <a
                    href={executionResult.prResult.prUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-cyan-400 hover:text-cyan-300 font-bold text-xs flex items-center space-x-1 mt-1 underline"
                  >
                    <span>PR #{executionResult.prResult.prNumber} (OPEN)</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                ) : (
                  <span className="text-amber-400">Pendente de PAT</span>
                )}
              </div>

              <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800 flex items-center justify-between">
                <div>
                  <span className="text-slate-400 block text-[11px]">Relatorio PDF:</span>
                  <span className="text-slate-200 text-xs">Compilado & Baixado</span>
                </div>
                <button
                  onClick={handleReDownloadPdf}
                  className="px-2.5 py-1.5 bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 rounded border border-cyan-500/30 flex items-center space-x-1 text-xs"
                >
                  <Download className="w-3 h-3" />
                  <span>Baixar</span>
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Tabs de Detalhes da Varredura Real */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="flex border-b border-slate-800 bg-slate-950/60 overflow-x-auto">
          <button
            onClick={() => setActiveTab('context')}
            className={`px-5 py-3 text-xs font-mono font-medium transition-all flex items-center space-x-2 border-b-2 ${
              activeTab === 'context'
                ? 'border-cyan-400 text-cyan-400 bg-slate-900'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>Contexto GraphRAG & DDD (Regra C44)</span>
          </button>

          <button
            onClick={() => setActiveTab('guarantees')}
            className={`px-5 py-3 text-xs font-mono font-medium transition-all flex items-center space-x-2 border-b-2 ${
              activeTab === 'guarantees'
                ? 'border-cyan-400 text-cyan-400 bg-slate-900'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldCheck className="w-4 h-4" />
            <span>Garantias On-Chain ({currentScan?.summary.securityScore}/100)</span>
          </button>

          <button
            onClick={() => setActiveTab('findings')}
            className={`px-5 py-3 text-xs font-mono font-medium transition-all flex items-center space-x-2 border-b-2 ${
              activeTab === 'findings'
                ? 'border-cyan-400 text-cyan-400 bg-slate-900'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Code2 className="w-4 h-4" />
            <span>Achados da AST ({currentScan?.findings.length || 0})</span>
          </button>

          <button
            onClick={() => setActiveTab('issues')}
            className={`px-5 py-3 text-xs font-mono font-medium transition-all flex items-center space-x-2 border-b-2 ${
              activeTab === 'issues'
                ? 'border-cyan-400 text-cyan-400 bg-slate-900'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <GitPullRequest className="w-4 h-4" />
            <span>Issues Criadas ({executionResult?.issuesResult.totalCreated || 0})</span>
          </button>

          <button
            onClick={() => setActiveTab('files')}
            className={`px-5 py-3 text-xs font-mono font-medium transition-all flex items-center space-x-2 border-b-2 ${
              activeTab === 'files'
                ? 'border-cyan-400 text-cyan-400 bg-slate-900'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-4 h-4" />
            <span>Arvore Fisica Inspecionada ({currentScan?.scannedFilesCount || 0})</span>
          </button>

          <button
            onClick={() => {
              setLearningState(getLearningState());
              setActiveTab('learning');
            }}
            className={`px-5 py-3 text-xs font-mono font-medium transition-all flex items-center space-x-2 border-b-2 ${
              activeTab === 'learning'
                ? 'border-purple-400 text-purple-300 bg-slate-900'
                : 'border-transparent text-slate-400 hover:text-purple-300'
            }`}
          >
            <Brain className="w-4 h-4 text-purple-400" />
            <span>Aprendizado Continuo ({learningState.totalPrEventsLearned} PRs)</span>
          </button>
        </div>

        <div className="p-6">
          {/* TAB CONTEXTO: GRAPHRAG, DDD, SOA & AST */}
          {activeTab === 'context' && (
            <div className="space-y-6">
              {/* Header Contextual */}
              <div className="p-4 rounded-xl bg-slate-950/80 border border-cyan-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
                      Arquitetura Contextual Integrada
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                      Regra C44: Nao-Destrutiva
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 mt-1 max-w-2xl">
                    {contextArch?.architecturalSummary || 'Inspecao em tempo real da arvore fisica de arquivos, grafo de dependencias GraphRAG e invariantes de dominio DDD.'}
                  </p>
                </div>
                <div className="text-right shrink-0">
                  <div className="text-[10px] font-mono text-slate-400">Score de Risco Semantico (GraphRAG):</div>
                  <div className={`text-lg font-mono font-black ${
                    (contextArch?.graphRag.crossInstructionRiskScore ?? 0) >= 85
                      ? 'text-emerald-400'
                      : (contextArch?.graphRag.crossInstructionRiskScore ?? 0) >= 60
                      ? 'text-amber-400'
                      : 'text-red-400'
                  }`}>
                    {contextArch ? `${contextArch.graphRag.crossInstructionRiskScore}%` : 'Calculando...'}
                    <span className="text-xs font-normal ml-1">
                      {contextArch
                        ? (contextArch.graphRag.crossInstructionRiskScore >= 85
                            ? '[MITIGADO]'
                            : contextArch.graphRag.crossInstructionRiskScore >= 60
                            ? '[ATENCAO]'
                            : '[VULNERAVEL]')
                        : ''}
                    </span>
                  </div>
                </div>
              </div>

              {/* Matriz de Invariantes DDD */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <ShieldCheck className="w-4 h-4 text-cyan-400" />
                    <h3 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
                      Invariantes do Bounded Context ({contextArch?.dddModel.boundedContext || 'SolanaAnchorCounterDomain'})
                    </h3>
                  </div>
                  <span className="text-[11px] font-mono text-slate-400">
                    Aggregate Root: <strong className="text-cyan-300">{contextArch?.dddModel.aggregateRoot || 'UserCounter'}</strong>
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {contextArch?.dddModel.invariants.map((inv) => (
                    <div
                      key={inv.id}
                      className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono font-bold text-slate-200">{inv.name}</span>
                        <span
                          className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                            inv.status === 'VERIFIED'
                              ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                              : 'bg-red-500/20 text-red-400 border border-red-500/30'
                          }`}
                        >
                          {inv.status}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400">{inv.description}</p>
                      <code className="block bg-slate-900 text-cyan-300 text-[10px] p-1.5 rounded font-mono border border-slate-800 overflow-x-auto">
                        Regra: {inv.formalRule}
                      </code>
                    </div>
                  ))}
                </div>
              </div>

              {/* Vetores de Ataque Semanticos GraphRAG */}
              <div className="space-y-3">
                <div className="flex items-center space-x-2">
                  <Cpu className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
                    Vetores de Ataque e Grafos de Dependencia (GraphRAG)
                  </h3>
                </div>

                <div className="space-y-3">
                  {contextArch?.graphRag.attackPaths.map((ap) => (
                    <div
                      key={ap.id}
                      className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <span className="text-xs font-mono font-bold text-cyan-400">[{ap.id}]</span>
                          <span className="text-xs font-semibold text-slate-200">{ap.title}</span>
                        </div>
                        <span
                          className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                            ap.status === 'MITIGATED'
                              ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                              : 'bg-red-500/20 text-red-400 border border-red-500/30'
                          }`}
                        >
                          {ap.status}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400"><strong>Objetivo do Atacante:</strong> {ap.attackerGoal}</p>
                      <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800 text-[11px] font-mono text-slate-300 space-y-1">
                        <div className="text-slate-400 font-bold text-[10px] uppercase">Cadeia de Inspecao Semantica:</div>
                        {ap.steps.map((st, sidx) => (
                          <div key={sidx} className="text-slate-300 pl-2 border-l border-slate-700">{st}</div>
                        ))}
                      </div>
                      <div className="text-[11px] font-mono text-emerald-400">
                        Mitigacao Verificada: {ap.mitigationInContract}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Rastreabilidade com Microservicos SOA */}
              <div className="space-y-3">
                <div className="flex items-center space-x-2">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
                    Catalogo Integrado de Microservicos SOA
                  </h3>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                  {contextArch?.soaServices.map((srv) => (
                    <div
                      key={srv.serviceId}
                      className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1"
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono font-bold text-cyan-400">{srv.serviceId}</span>
                        <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">{srv.status}</span>
                      </div>
                      <div className="text-xs font-semibold text-slate-200">{srv.name}</div>
                      <p className="text-[11px] text-slate-400 line-clamp-2">{srv.roleInAudit}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'guarantees' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="text-xs font-mono text-slate-400">Score Geral de Seguranca:</span>
                <span className="text-sm font-mono font-bold text-emerald-400">
                  {currentScan?.summary.securityScore}/100 [{currentScan?.summary.status}]
                </span>
              </div>

              <div className="space-y-3">
                    {currentScan?.findings.map((f, i) => (
                      <div
                        key={f.id || i}
                        className="p-3.5 rounded-xl border bg-slate-950/70 border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                      >
                        <div className="space-y-1 flex-1">
                          <div className="flex items-center space-x-2">
                            <span
                              className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                                f.severity === 'CRITICAL'
                                  ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                                  : f.severity === 'HIGH'
                                  ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                                  : f.severity === 'MEDIUM'
                                  ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                                  : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                              }`}
                            >
                              {f.severity}
                            </span>
                            <span className="text-xs font-semibold text-slate-200">{f.title}</span>
                          </div>
                          <p className="text-xs text-slate-400">{f.description}</p>
                          {f.snippet && (
                            <code className="block bg-slate-900 text-cyan-300 text-[11px] p-1.5 rounded font-mono border border-slate-800">
                              {f.snippet}
                            </code>
                          )}
                        </div>
                        <div className="flex sm:flex-col items-center sm:items-end justify-between sm:justify-center gap-2 shrink-0">
                          <span className="text-[10px] font-mono text-slate-500 whitespace-nowrap">
                            {f.file}:{f.line}
                          </span>
                          {f.severity !== 'PASS' && f.remediationCode && (
                            <button
                              onClick={() => handleOpenRemediationPreview(f)}
                              className="px-2.5 py-1 rounded bg-cyan-950/60 hover:bg-cyan-900/80 border border-cyan-500/30 hover:border-cyan-400 text-cyan-300 text-[11px] font-mono flex items-center space-x-1 transition-all"
                            >
                              <Columns className="w-3 h-3 text-cyan-400" />
                              <span>Diff Remediacao</span>
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
              </div>
            </div>
          )}

          {activeTab === 'findings' && (
            <div className="space-y-3">
              <p className="text-xs text-slate-400">
                Todos os achados derivam diretamente da inspecao em tempo real da AST dos smart contracts e arquivos do projeto:
              </p>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2 px-3">Severidade</th>
                      <th className="py-2 px-3">Regra</th>
                      <th className="py-2 px-3">Arquivo</th>
                      <th className="py-2 px-3">Linha</th>
                      <th className="py-2 px-3">Recomendacao</th>
                      <th className="py-2 px-3 text-right">Remediacao AST</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {currentScan?.findings.map((f, i) => (
                      <tr key={i} className="hover:bg-slate-800/40">
                        <td className="py-2 px-3">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] ${
                              f.severity === 'PASS'
                                ? 'text-emerald-400 bg-emerald-500/10'
                                : 'text-amber-400 bg-amber-500/10'
                            }`}
                          >
                            {f.severity}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-slate-300">{f.ruleId}</td>
                        <td className="py-2 px-3 text-cyan-400 truncate max-w-[180px]">{f.file}</td>
                        <td className="py-2 px-3 text-slate-400">{f.line}</td>
                        <td className="py-2 px-3 text-slate-400 truncate max-w-[260px]">{f.recommendation}</td>
                        <td className="py-2 px-3 text-right">
                          {f.severity !== 'PASS' && f.remediationCode ? (
                            <button
                              onClick={() => handleOpenRemediationPreview(f)}
                              className="px-2 py-0.5 rounded bg-cyan-950 hover:bg-cyan-900 border border-cyan-500/30 hover:border-cyan-400 text-cyan-300 text-[10px] font-mono inline-flex items-center space-x-1"
                              title="Visualizar diff lado a lado com correcao da AST"
                            >
                              <Columns className="w-2.5 h-2.5 text-cyan-400" />
                              <span>Diff</span>
                            </button>
                          ) : (
                            <span className="text-slate-600 text-[10px]">-</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeTab === 'issues' && (
            <div className="space-y-3">
              {executionResult?.issuesResult?.issues && executionResult.issuesResult.issues.length > 0 ? (
                <div className="space-y-2">
                  <p className="text-xs text-slate-400">
                    As seguintes issues foram submetidas com sucesso a API oficial do GitHub:
                  </p>
                  {executionResult.issuesResult.issues.map((iss) => (
                    <div
                      key={iss.id}
                      className="p-3 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between"
                    >
                      <div>
                        <span className="text-xs font-bold text-slate-200">
                          #{iss.number} {iss.title}
                        </span>
                        <span className="text-[10px] text-slate-500 font-mono block">
                          Status: {iss.state.toUpperCase()} | Severidade: {iss.severity}
                        </span>
                      </div>
                      <a
                        href={iss.htmlUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-cyan-400 hover:text-cyan-300 text-xs font-mono flex items-center space-x-1"
                      >
                        <span>Abrir no GitHub</span>
                        <ExternalLink className="w-3.5 h-3.5" />
                      </a>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-slate-500 text-xs font-mono">
                  Nenhuma issue gerada ainda. Clique no botao acima "Criar Issues" para executar o fluxo.
                </div>
              )}
            </div>
          )}

          {activeTab === 'files' && (
            <div className="space-y-2">
              <p className="text-xs text-slate-400">
                Arquivos reais e fisicos analisados pelo motor de auditoria (Zero Mocks):
              </p>
              <div className="space-y-1.5 font-mono text-xs">
                {currentScan?.filesScanned.map((f, i) => (
                  <div
                    key={i}
                    className="p-2 bg-slate-950 rounded border border-slate-800 flex items-center justify-between"
                  >
                    <span className="text-cyan-300">{f}</span>
                    <span className="text-[10px] text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded">
                      Inspecionado
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB APRENDIZADO CONTINUO & FINE-TUNING LOCAL */}
          {activeTab === 'learning' && (
            <div className="space-y-6 font-mono">
              <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-500/30 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center space-x-2">
                    <Brain className="w-5 h-5 text-purple-400 animate-pulse" />
                    <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                      Arquitetura de Fine-Tuning Local e Memoria de Aprendizado Continuo
                    </h3>
                  </div>
                  <p className="text-xs text-slate-400 mt-1 max-w-2xl">
                    O motor calibra dinamicamente a matriz de pesos de penalidade com base em feedbacks reais dos Pull Requests, comentarios resolvidos e correcoes de compilacao (zero dados estaticos).
                  </p>
                </div>

                <div className="text-right shrink-0">
                  <span className="text-[10px] text-purple-300 block">Eventos de PR Aprendidos:</span>
                  <span className="text-xl font-bold text-purple-400">
                    {learningState.totalPrEventsLearned} Ciclos
                  </span>
                </div>
              </div>

              {/* Contexto Inicial de Conhecimento Solana/Anchor */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-slate-200 uppercase flex items-center space-x-2">
                    <Sparkles className="w-4 h-4 text-cyan-400" />
                    <span>Conhecimento de Dominio Solana Anchor Incorporado</span>
                  </span>
                  <span className="text-[11px] text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded">
                    Ativo em Tempo Real
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 text-xs">
                  <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800/80">
                    <span className="text-[10px] text-slate-400 block font-semibold">Rent-Exempt Exato:</span>
                    <span className="text-emerald-400 font-bold">49 Bytes Exatos</span>
                    <span className="text-[10px] text-slate-500 block mt-0.5">8 disc + 32 auth + 8 count + 1 bump</span>
                  </div>
                  <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800/80">
                    <span className="text-[10px] text-slate-400 block font-semibold">Signers Ed25519:</span>
                    <span className="text-emerald-400 font-bold">Signer&lt;'info&gt; Obrigatorio</span>
                    <span className="text-[10px] text-slate-500 block mt-0.5">has_one = authority em mutacoes</span>
                  </div>
                  <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800/80">
                    <span className="text-[10px] text-slate-400 block font-semibold">Aritmetica SVM:</span>
                    <span className="text-emerald-400 font-bold">checked_add / checked_sub</span>
                    <span className="text-[10px] text-slate-500 block mt-0.5">Protecao de overflow/underflow</span>
                  </div>
                  <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800/80">
                    <span className="text-[10px] text-slate-400 block font-semibold">Discriminadores Anchor:</span>
                    <span className="text-emerald-400 font-bold">sha256("global:&lt;ix&gt;")</span>
                    <span className="text-[10px] text-slate-500 block mt-0.5">Primeiros 8 bytes exatos</span>
                  </div>
                  <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800/80">
                    <span className="text-[10px] text-slate-400 block font-semibold">Politica CI DevSecOps:</span>
                    <span className="text-emerald-400 font-bold">cargo check --locked</span>
                    <span className="text-[10px] text-slate-500 block mt-0.5">Zero fallbacks e sem || true</span>
                  </div>
                  <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800/80">
                    <span className="text-[10px] text-slate-400 block font-semibold">Seeds de PDA:</span>
                    <span className="text-emerald-400 font-bold">Canonical Bump Salvo</span>
                    <span className="text-[10px] text-slate-500 block mt-0.5">Minimiza Compute Units (CU)</span>
                  </div>
                </div>
              </div>

              {/* Matriz de Pesos de Penalidade Dinamica */}
              <div className="space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <h4 className="font-bold text-slate-200 uppercase">
                    Matriz de Pesos e Penalidades Adaptativas do Modelo
                  </h4>
                  <span className="text-slate-400 text-[11px]">
                    Ultima calibracao: {new Date(learningState.updatedAt).toLocaleTimeString()}
                  </span>
                </div>

                <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-950">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400">
                        <th className="py-2.5 px-3">Regra de Seguranca</th>
                        <th className="py-2.5 px-3">Categoria</th>
                        <th className="py-2.5 px-3">Severidade</th>
                        <th className="py-2.5 px-3 text-center">Peso Ponderado</th>
                        <th className="py-2.5 px-3 text-center">Reforcos Aprendidos</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/50">
                      {Object.values(learningState.weights).map((w) => (
                        <tr key={w.ruleId} className="hover:bg-slate-900/40">
                          <td className="py-2.5 px-3">
                            <span className="text-slate-200 font-bold block">{w.name}</span>
                            <span className="text-[10px] text-slate-500">{w.ruleId}</span>
                          </td>
                          <td className="py-2.5 px-3">
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-cyan-300">
                              {w.category}
                            </span>
                          </td>
                          <td className="py-2.5 px-3">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              w.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                              w.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400' :
                              w.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-400' :
                              'bg-cyan-500/20 text-cyan-300'
                            }`}>
                              {w.severity}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-center">
                            <span className="text-purple-300 font-bold bg-purple-500/10 px-2 py-0.5 rounded border border-purple-500/30">
                              {w.weight} pts
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-center text-slate-300">
                            {w.reinforcementsCount}x
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Historico de Feedbacks Absorvidos */}
              <div className="space-y-3">
                <h4 className="text-xs font-bold text-slate-200 uppercase">
                  Historico de Feedbacks e Ajustes no Ciclo de Pull Requests
                </h4>

                <div className="space-y-2">
                  {learningState.history.map((ev) => (
                    <div
                      key={ev.id}
                      className="p-3 bg-slate-950 rounded-xl border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                    >
                      <div>
                        <div className="flex items-center space-x-2">
                          <span className="text-[10px] bg-purple-500/20 text-purple-300 border border-purple-500/30 px-2 py-0.5 rounded font-bold">
                            {ev.source}
                          </span>
                          <span className="text-slate-300 font-bold">{ev.ruleId}</span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">{ev.explanation}</p>
                      </div>

                      <div className="text-right shrink-0">
                        <span className="text-emerald-400 font-bold text-[11px] block">
                          +{ev.deltaWeight} pts de rigor
                        </span>
                        <span className="text-[10px] text-slate-500">
                          {new Date(ev.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Preview Remediation Side-by-Side Diff Modal */}
      <PreviewRemediationModal
        isOpen={isPreviewOpen}
        onClose={() => setIsPreviewOpen(false)}
        finding={previewFinding}
        currentCode={previewSourceCode}
        onApplyFix={(patchedCode) => {
          setPreviewSourceCode(patchedCode);
          setIsPreviewOpen(false);
        }}
      />
    </div>
  );
}
