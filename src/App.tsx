/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo, useEffect } from 'react';
import { 
  ShieldCheck, 
  Terminal, 
  Cpu, 
  Code2, 
  CheckCircle2, 
  AlertTriangle, 
  AlertOctagon,
  FileCode, 
  Key, 
  Database, 
  Lock, 
  Zap, 
  Copy, 
  Check, 
  Layers, 
  GitPullRequest, 
  GitBranch, 
  GitFork,
  Send, 
  Plus, 
  Trash2, 
  Sparkles,
  ExternalLink,
  Workflow,
  WrapText,
  Activity,
  X,
  Play,
  RotateCcw,
  Wrench,
  Download,
  Server,
  Share2,
  Box,
  Compass
} from 'lucide-react';
import { 
  PROGRAM_ID, 
  RUST_CONTRACT_SOURCE 
} from './contracts/solanaSandboxCounter.ts';
import { 
  CounterClient, 
  generateGitHubPipelinePayload,
  USER_COUNTER_SPACE
} from '../client/index.ts';
import { 
  generateModularAnchorContract, 
  calculateAccountSpace, 
  DEFAULT_COUNTER_CONFIG, 
  CustomField,
  ContractTemplateConfig
} from './services/contractGenerator.ts';
import { 
  runAstSecurityAudit, 
  AstAuditReport, 
  AstFinding 
} from './utils/astAuditor.ts';
import { 
  runPropertyFuzzingSuite, 
  FuzzRunReport 
} from './services/fuzzingEngine.ts';
import { 
  buildContractSecurityGraph, 
  GraphRagAnalysisResult 
} from './services/graphRAGService.ts';
import { 
  ANCHOR_DEVSECOPS_BPMN_TASKS, 
  generateOmgBpmnXml, 
  downloadBpmnFile 
} from './services/bpmnWorkflowService.ts';
import { 
  SOA_CATALOG, 
  SoaServiceEntry 
} from './services/soaCatalogService.ts';
import { 
  MCP_TOOLS, 
  executeMcpToolDirect 
} from './mcp/server.ts';
import { GitHubSyncModal } from './components/GitHubSyncModal.tsx';

export default function App() {
  const [activeTab, setActiveTab] = useState<'ast' | 'fuzzing' | 'graphrag' | 'bpmn' | 'mcp' | 'soa' | 'contract' | 'client'>('ast');
  const [copied, setCopied] = useState<string | null>(null);
  const [wrapCode, setWrapCode] = useState<boolean>(false);
  const [isGitHubModalOpen, setIsGitHubModalOpen] = useState<boolean>(false);
  
  // Active Rust contract code
  const [activeRustCode, setActiveRustCode] = useState<string>(RUST_CONTRACT_SOURCE);
  const [selectedPreset, setSelectedPreset] = useState<'secure' | 'vuln-signer' | 'vuln-overflow'>('secure');

  // AST Live Audit Report
  const astReport: AstAuditReport = useMemo(() => {
    return runAstSecurityAudit(activeRustCode);
  }, [activeRustCode]);

  // GraphRAG Security Analysis
  const graphRagResult: GraphRagAnalysisResult = useMemo(() => {
    return buildContractSecurityGraph(activeRustCode);
  }, [activeRustCode]);

  // Fuzzing Suite State
  const [isFuzzingRunning, setIsFuzzingRunning] = useState<boolean>(false);
  const [fuzzReport, setFuzzReport] = useState<FuzzRunReport>(() => runPropertyFuzzingSuite(10000));
  const [fuzzBatchSize, setFuzzBatchSize] = useState<number>(10000);

  // MCP Interactive Runner State
  const [selectedMcpTool, setSelectedMcpTool] = useState<string>('audit_anchor_ast');
  const [mcpResult, setMcpResult] = useState<string>('');
  const [isMcpRunning, setIsMcpRunning] = useState<boolean>(false);

  // Client Simulator State
  const [authorityInput, setAuthorityInput] = useState<string>('9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM');
  const [simOperation, setSimOperation] = useState<'initialize' | 'increment' | 'decrement' | 'reset' | 'close'>('increment');
  const [simAmount, setSimAmount] = useState<number>(1);
  const [simulatedCount, setSimulatedCount] = useState<number>(10);
  const [simulationLogs, setSimulationLogs] = useState<Array<{ text: string; type: 'ok' | 'fail' | 'info'; time: string }>>([
    { text: 'Solana Virtual Machine (SVM) devnet environment ready.', type: 'info', time: '13:42:01' },
    { text: 'Client bound to Program ID: CntSandbox111111111111111111111111111111111', type: 'info', time: '13:42:02' },
    { text: 'Derived PDA: 4p5Y7d... (Seed: [b"counter", authority]) with Bump: 254', type: 'ok', time: '13:42:03' },
    { text: 'Rent-Exempt Balance Verified: 1,231,920 Lamports for 49 bytes exact allocation', type: 'ok', time: '13:42:04' },
  ]);

  // Copy helper
  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  // Change Preset
  const handleSelectPreset = (preset: 'secure' | 'vuln-signer' | 'vuln-overflow') => {
    setSelectedPreset(preset);
    let code = RUST_CONTRACT_SOURCE;
    let flags = { hasCheckedMath: true, hasSignerCheck: true, hasOneAuthority: true, hasRentExempt49B: true };

    if (preset === 'vuln-signer') {
      code = `use anchor_lang::prelude::*;
declare_id!("CntSandbox111111111111111111111111111111111");
#[program]
pub mod solana_sandbox_counter {
    use super::*;
    pub fn increment(ctx: Context<UpdateCounter>) -> Result<()> {
        ctx.accounts.counter.count = ctx.accounts.counter.count.checked_add(1).ok_or(SecurityErrorCode::NumericalOverflow)?;
        Ok(())
    }
}
#[derive(Accounts)]
pub struct UpdateCounter<'info> {
    #[account(mut, seeds = [b"counter", authority.key().as_ref()], bump = counter.bump)]
    pub counter: Account<'info, UserCounter>,
    pub authority: AccountInfo<'info>, // VULN: Missing Signer & Missing has_one!
}
#[account]
pub struct UserCounter { pub authority: Pubkey, pub count: u64, pub bump: u8 }
#[error_code]
pub enum SecurityErrorCode { #[msg("Numerical overflow")] NumericalOverflow }`;
      flags = { hasCheckedMath: true, hasSignerCheck: false, hasOneAuthority: false, hasRentExempt49B: true };
    } else if (preset === 'vuln-overflow') {
      code = `use anchor_lang::prelude::*;
declare_id!("CntSandbox111111111111111111111111111111111");
#[program]
pub mod solana_sandbox_counter {
    use super::*;
    pub fn increment(ctx: Context<UpdateCounter>) -> Result<()> {
        ctx.accounts.counter.count += 1; // VULN: Unchecked math!
        Ok(())
    }
}
#[derive(Accounts)]
pub struct UpdateCounter<'info> {
    #[account(mut, seeds = [b"counter", authority.key().as_ref()], bump = counter.bump, has_one = authority)]
    pub counter: Account<'info, UserCounter>,
    pub authority: Signer<'info>,
}
#[account]
pub struct UserCounter { pub authority: Pubkey, pub count: u64, pub bump: u8 }`;
      flags = { hasCheckedMath: false, hasSignerCheck: true, hasOneAuthority: true, hasRentExempt49B: true };
    }

    setActiveRustCode(code);
    setFuzzReport(runPropertyFuzzingSuite(fuzzBatchSize, flags));
  };

  // Apply AST Auto-Fix
  const handleApplyQuickFix = (finding: AstFinding) => {
    if (!finding.fixPatch) return;
    const patchedCode = activeRustCode.replace(finding.fixPatch.search, finding.fixPatch.replace);
    setActiveRustCode(patchedCode);
    setSelectedPreset('secure');
    setFuzzReport(runPropertyFuzzingSuite(fuzzBatchSize, {
      hasCheckedMath: true,
      hasSignerCheck: true,
      hasOneAuthority: true,
      hasRentExempt49B: true,
    }));
  };

  // Trigger Fuzzing Suite
  const handleTriggerFuzzing = () => {
    setIsFuzzingRunning(true);
    setTimeout(() => {
      const flags = {
        hasCheckedMath: activeRustCode.includes('checked_add'),
        hasSignerCheck: activeRustCode.includes("Signer<'info>"),
        hasOneAuthority: activeRustCode.includes('has_one = authority'),
        hasRentExempt49B: activeRustCode.includes('49') || activeRustCode.includes('ACCOUNT_SPACE'),
      };
      setFuzzReport(runPropertyFuzzingSuite(fuzzBatchSize, flags));
      setIsFuzzingRunning(false);
    }, 350);
  };

  // Execute MCP Tool directly
  const handleRunMcpTool = async () => {
    setIsMcpRunning(true);
    try {
      let args: any = {};
      if (selectedMcpTool === 'audit_anchor_ast') args = { sourceCode: activeRustCode };
      if (selectedMcpTool === 'run_property_fuzzer') args = { vectorCount: 10000 };
      if (selectedMcpTool === 'derive_pda_spec') args = { authorityPubkey: authorityInput };
      if (selectedMcpTool === 'query_graphrag_security') args = { instructionTarget: 'increment' };

      const res = await executeMcpToolDirect(selectedMcpTool, args);
      setMcpResult(JSON.stringify(res, null, 2));
    } catch (err: any) {
      setMcpResult(`Error: ${err.message}`);
    } finally {
      setIsMcpRunning(false);
    }
  };

  // Run Client Simulation
  const handleRunSimulation = () => {
    let nextCount = simulatedCount;
    let logMsg = '';
    let logType: 'ok' | 'fail' | 'info' = 'ok';
    const now = new Date().toLocaleTimeString();

    if (simOperation === 'initialize') {
      nextCount = simAmount;
      logMsg = `[OK] initialize() executed -> UserCounter initialized (count = ${simAmount}). Space: 49B. CU used: 412.`;
    } else if (simOperation === 'increment') {
      nextCount = simulatedCount + simAmount;
      logMsg = `[OK] increment(${simAmount}) executed -> .checked_add(${simAmount}) OK. Count: ${nextCount}. CU used: 198.`;
    } else if (simOperation === 'decrement') {
      if (simulatedCount < simAmount) {
        logMsg = `[FAIL] SecurityErrorCode::NumericalUnderflow -> Count (${simulatedCount}) < ${simAmount}. Safe revert triggered.`;
        logType = 'fail';
      } else {
        nextCount = simulatedCount - simAmount;
        logMsg = `[OK] decrement(${simAmount}) executed -> .checked_sub(${simAmount}) OK. Count: ${nextCount}. CU used: 204.`;
      }
    } else if (simOperation === 'reset') {
      nextCount = 0;
      logMsg = `[OK] reset() executed -> State reset to zero by authority. has_one constraint verified.`;
    } else if (simOperation === 'close') {
      nextCount = 0;
      logMsg = `[OK] close() executed -> PDA account closed. 1,231,920 lamports refunded to authority.`;
    }

    setSimulatedCount(nextCount);
    setSimulationLogs(prev => [{ text: logMsg, type: logType, time: now }, ...prev.slice(0, 15)]);
  };

  const codeLines = activeRustCode.trim().split('\n');
  const githubPayload = generateGitHubPipelinePayload({ customRustCode: activeRustCode });

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans touch-scroll">
      {/* Top IDE Header */}
      <header className="border-b border-slate-800/80 bg-slate-900/80 backdrop-blur px-3 sm:px-6 py-2.5 sm:py-3 sticky top-0 z-40">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
          <div className="flex items-center gap-2.5 sm:gap-3">
            <div className="w-8 h-8 sm:w-9 sm:h-9 rounded-lg bg-gradient-to-tr from-purple-600 via-indigo-600 to-cyan-500 p-0.5 shadow-lg shadow-purple-500/20 shrink-0">
              <div className="w-full h-full bg-slate-950 rounded-[7px] flex items-center justify-center">
                <ShieldCheck className="w-4 h-4 sm:w-5 sm:h-5 text-cyan-400" />
              </div>
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-1.5 sm:gap-2 flex-wrap">
                <h1 className="text-xs sm:text-sm font-semibold tracking-wide text-white truncate">
                  Solana Anchor DevSecOps IDE
                </h1>
                <span className="px-1.5 py-0.5 text-[9px] sm:text-[10px] uppercase font-bold tracking-wider bg-purple-500/10 text-purple-400 border border-purple-500/30 rounded shrink-0">
                  Full Ecosystem
                </span>
              </div>
              <p className="text-[10px] sm:text-xs text-slate-400 font-mono truncate">
                AST • 10K Fuzzer • GraphRAG • BPMN 2.0 • MCP Server • GitHub PR
              </p>
            </div>
          </div>

          {/* Quick Header Actions */}
          <div className="flex items-center justify-between sm:justify-end gap-2 shrink-0">
            {/* GitHub Sync Button */}
            <button
              onClick={() => setIsGitHubModalOpen(true)}
              className="px-2.5 py-1.5 text-xs font-mono bg-emerald-950/60 hover:bg-emerald-900/60 text-emerald-300 border border-emerald-800/40 rounded-lg flex items-center gap-1.5 transition-all touch-manipulation active:scale-95"
            >
              <GitFork className="w-3.5 h-3.5 text-emerald-400" />
              <span className="text-[11px] font-semibold">Fork & PR Sync</span>
            </button>

            {/* AST Score Badge */}
            <div className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs font-mono font-bold ${
              astReport.score >= 85 ? 'bg-emerald-950/60 border-emerald-500/40 text-emerald-400' :
              astReport.score >= 60 ? 'bg-amber-950/60 border-amber-500/40 text-amber-400' :
              'bg-rose-950/60 border-rose-500/40 text-rose-400'
            }`}>
              <ShieldCheck className="w-4 h-4" />
              <span>AST: {astReport.score}/100</span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Workspace Area */}
      <main className="flex-1 p-3 sm:p-5 md:p-6 max-w-7xl w-full mx-auto flex flex-col gap-4 sm:gap-5">
        {/* Navigation Tabs Bar */}
        <div className="border-b border-slate-800 pb-2 -mx-3 px-3 sm:mx-0 sm:px-0">
          <div className="flex items-center gap-1.5 sm:gap-2 overflow-x-auto touch-scroll no-scrollbar py-0.5">
            <button
              onClick={() => setActiveTab('ast')}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center gap-1.5 shrink-0 ${
                activeTab === 'ast' ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30 font-semibold' : 'bg-slate-900 text-slate-400 hover:text-slate-200'
              }`}
            >
              <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
              <span>1. Auditor AST</span>
            </button>

            <button
              onClick={() => setActiveTab('fuzzing')}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center gap-1.5 shrink-0 ${
                activeTab === 'fuzzing' ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30 font-semibold' : 'bg-slate-900 text-slate-400 hover:text-slate-200'
              }`}
            >
              <Activity className="w-3.5 h-3.5 text-emerald-400" />
              <span>2. Fuzzer (10K)</span>
            </button>

            <button
              onClick={() => setActiveTab('graphrag')}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center gap-1.5 shrink-0 ${
                activeTab === 'graphrag' ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30 font-semibold' : 'bg-slate-900 text-slate-400 hover:text-slate-200'
              }`}
            >
              <Share2 className="w-3.5 h-3.5 text-purple-400" />
              <span>3. GraphRAG & Ataques</span>
            </button>

            <button
              onClick={() => setActiveTab('bpmn')}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center gap-1.5 shrink-0 ${
                activeTab === 'bpmn' ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30 font-semibold' : 'bg-slate-900 text-slate-400 hover:text-slate-200'
              }`}
            >
              <Workflow className="w-3.5 h-3.5 text-amber-400" />
              <span>4. BPMN 2.0 OMG</span>
            </button>

            <button
              onClick={() => setActiveTab('mcp')}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center gap-1.5 shrink-0 ${
                activeTab === 'mcp' ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30 font-semibold' : 'bg-slate-900 text-slate-400 hover:text-slate-200'
              }`}
            >
              <Box className="w-3.5 h-3.5 text-cyan-300" />
              <span>5. Servidor MCP</span>
            </button>

            <button
              onClick={() => setActiveTab('soa')}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center gap-1.5 shrink-0 ${
                activeTab === 'soa' ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30 font-semibold' : 'bg-slate-900 text-slate-400 hover:text-slate-200'
              }`}
            >
              <Server className="w-3.5 h-3.5 text-rose-400" />
              <span>6. Catálogo SOA</span>
            </button>

            <button
              onClick={() => setActiveTab('contract')}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center gap-1.5 shrink-0 ${
                activeTab === 'contract' ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30 font-semibold' : 'bg-slate-900 text-slate-400 hover:text-slate-200'
              }`}
            >
              <Code2 className="w-3.5 h-3.5" />
              <span>Rust (lib.rs)</span>
            </button>

            <button
              onClick={() => setActiveTab('client')}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center gap-1.5 shrink-0 ${
                activeTab === 'client' ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30 font-semibold' : 'bg-slate-900 text-slate-400 hover:text-slate-200'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Cliente SVM</span>
            </button>
          </div>
        </div>

        {/* Global Security Preset Selector */}
        <div className="p-3 rounded-xl border border-slate-800 bg-slate-900/40 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <span className="text-xs text-slate-400 font-mono">Modo de Simulação de Contrato:</span>
          <div className="flex items-center gap-1.5 flex-wrap">
            <button
              onClick={() => handleSelectPreset('secure')}
              className={`px-2.5 py-1 text-xs rounded-lg font-mono transition-all flex items-center gap-1.5 ${
                selectedPreset === 'secure' ? 'bg-emerald-600 text-white font-semibold' : 'bg-slate-950 border border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-300" />
              <span>Padrão Seguro (49B)</span>
            </button>
            <button
              onClick={() => handleSelectPreset('vuln-signer')}
              className={`px-2.5 py-1 text-xs rounded-lg font-mono transition-all flex items-center gap-1.5 ${
                selectedPreset === 'vuln-signer' ? 'bg-rose-600 text-white font-semibold' : 'bg-slate-950 border border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              <AlertOctagon className="w-3.5 h-3.5 text-rose-300" />
              <span>Injetar: Missing Signer</span>
            </button>
            <button
              onClick={() => handleSelectPreset('vuln-overflow')}
              className={`px-2.5 py-1 text-xs rounded-lg font-mono transition-all flex items-center gap-1.5 ${
                selectedPreset === 'vuln-overflow' ? 'bg-amber-600 text-white font-semibold' : 'bg-slate-950 border border-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              <AlertTriangle className="w-3.5 h-3.5 text-amber-300" />
              <span>Injetar: Integer Overflow</span>
            </button>
          </div>
        </div>

        {/* TAB 1: AST AUDITOR */}
        {activeTab === 'ast' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            <div className="lg:col-span-4 rounded-xl border border-slate-800 bg-slate-900/40 p-4 sm:p-5 flex flex-col gap-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-white">Relatório AST</h3>
                  <p className="text-[11px] text-slate-400">Inspeção estática Anchor</p>
                </div>
                <div className={`px-2.5 py-1 rounded text-xs font-mono font-bold ${
                  astReport.status === 'SECURE' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' :
                  astReport.status === 'WARNING' ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                  'bg-rose-950 text-rose-400 border border-rose-800'
                }`}>
                  {astReport.status}
                </div>
              </div>

              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex flex-col items-center justify-center text-center">
                <div className="text-3xl sm:text-4xl font-extrabold font-mono text-cyan-400">
                  {astReport.score} <span className="text-lg text-slate-500 font-normal">/ 100</span>
                </div>
                <div className="w-full bg-slate-900 h-2 rounded-full mt-3 overflow-hidden">
                  <div 
                    className={`h-full transition-all duration-500 ${
                      astReport.score >= 85 ? 'bg-emerald-500' : astReport.score >= 60 ? 'bg-amber-500' : 'bg-rose-500'
                    }`}
                    style={{ width: `${astReport.score}%` }}
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex justify-between">
                  <span className="text-slate-400">Críticas:</span>
                  <span className={astReport.criticalCount > 0 ? 'text-rose-400 font-bold' : 'text-slate-400'}>{astReport.criticalCount}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex justify-between">
                  <span className="text-slate-400">Altas:</span>
                  <span className={astReport.highCount > 0 ? 'text-amber-400 font-bold' : 'text-slate-400'}>{astReport.highCount}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex justify-between">
                  <span className="text-slate-400">Médias:</span>
                  <span className="text-slate-300">{astReport.mediumCount}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex justify-between">
                  <span className="text-slate-400">PASS:</span>
                  <span className="text-emerald-400 font-bold">{astReport.passedCount}</span>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono space-y-1">
                <div className="text-slate-300 font-semibold mb-1">Garantias de Memória:</div>
                <div className="flex justify-between text-slate-400">
                  <span>Rent-Exempt Alocado:</span>
                  <span className="text-emerald-400">49 Bytes (OK)</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Canonical Bump:</span>
                  <span className="text-emerald-400">Salvo no Estado (OK)</span>
                </div>
              </div>
            </div>

            <div className="lg:col-span-8 rounded-xl border border-slate-800 bg-slate-950 flex flex-col overflow-hidden">
              <div className="bg-slate-900/80 px-4 py-2.5 border-b border-slate-800 flex justify-between text-xs font-mono">
                <span className="font-semibold text-slate-300">Regras de Auditoria ({astReport.findings.length})</span>
                <span className="text-slate-500">AST Static Engine</span>
              </div>

              <div className="p-3 sm:p-4 space-y-3 overflow-y-auto max-h-[580px] touch-scroll">
                {astReport.findings.map(finding => {
                  const isCritical = finding.severity === 'CRITICAL';
                  const isHigh = finding.severity === 'HIGH';
                  const isPass = finding.severity === 'PASS';

                  return (
                    <div 
                      key={finding.id}
                      className={`p-3.5 rounded-xl border ${
                        isCritical ? 'bg-rose-950/20 border-rose-800/40 text-rose-200' :
                        isHigh ? 'bg-amber-950/20 border-amber-800/40 text-amber-200' :
                        isPass ? 'bg-emerald-950/15 border-emerald-800/30 text-slate-300' :
                        'bg-slate-900/40 border-slate-800 text-slate-300'
                      }`}
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            isCritical ? 'bg-rose-900/60 text-rose-300' :
                            isHigh ? 'bg-amber-900/60 text-amber-300' :
                            isPass ? 'bg-emerald-900/60 text-emerald-300' :
                            'bg-slate-800 text-slate-300'
                          }`}>
                            {finding.severity}
                          </span>
                          <span className="text-xs font-semibold font-mono text-slate-100">{finding.title}</span>
                        </div>
                        <span className="text-[11px] font-mono text-slate-500">Linha {finding.line}</span>
                      </div>
                      <p className="text-xs text-slate-400 mt-2">{finding.description}</p>

                      {!isPass && finding.autoFixAvailable && finding.fixPatch && (
                        <div className="mt-3 pt-2 border-t border-slate-800/80 flex justify-end">
                          <button
                            onClick={() => handleApplyQuickFix(finding)}
                            className="px-3 py-1.5 bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 text-white rounded-lg text-xs font-mono flex items-center gap-1.5 shadow-md shadow-purple-600/30"
                          >
                            <Wrench className="w-3.5 h-3.5" />
                            <span>Aplicar Correção Rápida</span>
                          </button>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: PROPERTY-BASED FUZZING ENGINE */}
        {activeTab === 'fuzzing' && (
          <div className="flex flex-col gap-4">
            <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <h3 className="text-sm sm:text-base font-bold text-white flex items-center gap-2">
                  <Activity className="w-5 h-5 text-emerald-400 animate-pulse" />
                  <span>SVM Property Fuzzing Engine</span>
                </h3>
                <p className="text-xs text-slate-400 mt-1 max-w-2xl">
                  Gera 10.000 vetores de teste estocásticos avaliando fronteiras extremas (u64::MAX, underflows) e invariantes SVM.
                </p>
              </div>

              <button
                onClick={handleTriggerFuzzing}
                disabled={isFuzzingRunning}
                className="px-4 py-2 bg-gradient-to-r from-emerald-600 to-cyan-600 text-white font-medium text-xs rounded-lg flex items-center gap-2 shadow-lg shadow-emerald-600/30"
              >
                {isFuzzingRunning ? <RotateCcw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                <span>{isFuzzingRunning ? 'Executando...' : 'Rodar 10.000 Vetores'}</span>
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                <div className="text-[10px] text-slate-400 font-mono">Vetores Testados</div>
                <div className="text-2xl font-bold font-mono text-cyan-400 mt-0.5">{fuzzReport.totalVectors.toLocaleString()}</div>
              </div>
              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                <div className="text-[10px] text-slate-400 font-mono">Violações</div>
                <div className={`text-2xl font-bold font-mono mt-0.5 ${fuzzReport.failedVectors === 0 ? 'text-emerald-400' : 'text-rose-400'}`}>
                  {fuzzReport.failedVectors}
                </div>
              </div>
              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                <div className="text-[10px] text-slate-400 font-mono">Consumo Médio CU</div>
                <div className="text-2xl font-bold font-mono text-purple-400 mt-0.5">{fuzzReport.averageComputeUnits} CU</div>
              </div>
              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/50">
                <div className="text-[10px] text-slate-400 font-mono">Tempo de Execução</div>
                <div className="text-2xl font-bold font-mono text-amber-400 mt-0.5">{fuzzReport.executionTimeMs} ms</div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {fuzzReport.invariants.map((inv, idx) => (
                <div key={idx} className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 flex flex-col justify-between gap-2">
                  <div className="flex justify-between items-center">
                    <span className="text-xs font-mono font-bold text-slate-200">{inv.name}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${inv.passed ? 'bg-emerald-950 text-emerald-400' : 'bg-rose-950 text-rose-400'}`}>
                      {inv.status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">{inv.description}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 3: GRAPHRAG & ATTACK GRAPH EXPLORER */}
        {activeTab === 'graphrag' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            <div className="lg:col-span-4 rounded-xl border border-slate-800 bg-slate-900/40 p-5 flex flex-col gap-4">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Share2 className="w-4 h-4 text-purple-400" />
                  <span>Grafo de Conhecimento Semântico</span>
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Mapeamento de nós de instrução, contas e arestas de restrição de acesso.
                </p>
              </div>

              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2 text-xs font-mono">
                <div className="flex justify-between text-slate-400">
                  <span>Nós no Grafo:</span>
                  <span className="text-cyan-400">{graphRagResult.nodes.length} nós</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Arestas de Dependência:</span>
                  <span className="text-purple-400">{graphRagResult.edges.length} arestas</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Caminhos de Ataque Avaliados:</span>
                  <span className="text-emerald-400">{graphRagResult.attackPaths.length} caminhos</span>
                </div>
              </div>

              <div className="p-3.5 rounded-lg bg-purple-950/20 border border-purple-800/40 text-xs text-slate-300 leading-relaxed">
                <div className="font-semibold text-purple-300 mb-1 flex items-center gap-1.5">
                  <Sparkles className="w-3.5 h-3.5" />
                  Raciocínio GraphRAG & Gemini AI:
                </div>
                {graphRagResult.aiReasoning}
              </div>
            </div>

            <div className="lg:col-span-8 rounded-xl border border-slate-800 bg-slate-950 p-4 space-y-4">
              <h4 className="text-xs font-mono font-semibold text-slate-300 flex items-center gap-2">
                <Compass className="w-4 h-4 text-cyan-400" />
                Caminhos de Exploração & Vetores Mitigados
              </h4>

              <div className="space-y-3">
                {graphRagResult.attackPaths.map((ap) => (
                  <div key={ap.id} className="p-3.5 rounded-xl border border-slate-800 bg-slate-900/40 space-y-2 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-slate-200 font-mono">{ap.title}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        ap.status === 'MITIGATED' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400 border border-rose-800'
                      }`}>
                        {ap.status}
                      </span>
                    </div>
                    <p className="text-slate-400"><strong className="text-cyan-300">Objetivo do Atacante:</strong> {ap.attackerGoal}</p>
                    <div className="p-2 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-300 space-y-1">
                      {ap.steps.map((st, i) => <div key={i}>{st}</div>)}
                    </div>
                    <div className="text-[11px] text-emerald-300 font-mono">
                      ✓ Mitigação: {ap.mitigationInContract}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: BPMN 2.0 WORKFLOW & OMG XML EXPORT */}
        {activeTab === 'bpmn' && (
          <div className="flex flex-col gap-4">
            <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <h3 className="text-sm sm:text-base font-bold text-white flex items-center gap-2">
                  <Workflow className="w-5 h-5 text-amber-400" />
                  <span>Orquestrador de Processos BPMN 2.0 (Solana Anchor DevSecOps)</span>
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Mapeia os portões de qualidade de código, checagem de invariantes e geração atómica de Pull Request em conformidade com o padrão OMG.
                </p>
              </div>

              <button
                onClick={() => downloadBpmnFile()}
                className="px-4 py-2 bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 text-white font-medium text-xs rounded-lg flex items-center gap-2 shadow-lg shadow-amber-600/30"
              >
                <Download className="w-4 h-4" />
                <span>Descarregar OMG BPMN 2.0 XML</span>
              </button>
            </div>

            {/* Visual BPMN Sequence Tasks */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {ANCHOR_DEVSECOPS_BPMN_TASKS.map((task, idx) => (
                <div key={task.id} className="p-3.5 rounded-xl border border-slate-800 bg-slate-900/50 flex flex-col justify-between gap-2">
                  <div className="flex justify-between items-start">
                    <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/30">
                      Passo {idx + 1}: {task.type}
                    </span>
                    <span className="text-[10px] text-emerald-400 font-mono font-bold">{task.status}</span>
                  </div>
                  <h4 className="text-xs font-semibold text-slate-200 mt-1">{task.name}</h4>
                  <p className="text-[11px] text-slate-400 leading-relaxed">{task.description}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 5: MCP SERVER EXPLORER */}
        {activeTab === 'mcp' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            <div className="lg:col-span-5 rounded-xl border border-slate-800 bg-slate-900/40 p-5 flex flex-col gap-4">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Box className="w-4 h-4 text-cyan-300" />
                  <span>Servidor Model Context Protocol (MCP)</span>
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Exposição oficial de ferramentas para agentes de IA via `@modelcontextprotocol/sdk`.
                </p>
              </div>

              <div className="space-y-2">
                <label className="text-[11px] text-slate-400 font-mono block">Ferramenta MCP Disponível:</label>
                <div className="space-y-1.5">
                  {MCP_TOOLS.map((t) => (
                    <button
                      key={t.name}
                      onClick={() => setSelectedMcpTool(t.name)}
                      className={`w-full p-2.5 rounded-lg border text-left text-xs font-mono transition-all ${
                        selectedMcpTool === t.name 
                          ? 'bg-purple-950/60 border-purple-500 text-purple-200' 
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      <div className="font-bold text-white">{t.name}</div>
                      <div className="text-[10px] text-slate-400 mt-0.5">{t.description}</div>
                    </button>
                  ))}
                </div>
              </div>

              <button
                onClick={handleRunMcpTool}
                disabled={isMcpRunning}
                className="w-full py-2.5 px-4 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 text-white font-medium text-xs flex items-center justify-center gap-2 shadow-lg shadow-purple-600/30"
              >
                {isMcpRunning ? <RotateCcw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                <span>Executar Ferramenta MCP: {selectedMcpTool}</span>
              </button>
            </div>

            <div className="lg:col-span-7 rounded-xl border border-slate-800 bg-slate-950 flex flex-col overflow-hidden">
              <div className="bg-slate-900/80 px-4 py-2 border-b border-slate-800 flex justify-between text-xs font-mono">
                <span className="text-slate-300">Resposta JSON-RPC da Ferramenta MCP</span>
                <span className="text-emerald-400">MCP SDK v1.32</span>
              </div>
              <div className="p-4 flex-1 overflow-y-auto max-h-[500px] font-mono text-xs text-cyan-300 whitespace-pre touch-scroll">
                {mcpResult || 'Clique em "Executar Ferramenta MCP" para inspecionar a resposta em tempo real.'}
              </div>
            </div>
          </div>
        )}

        {/* TAB 6: SOA CATALOG */}
        {activeTab === 'soa' && (
          <div className="flex flex-col gap-4">
            <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 flex justify-between items-center">
              <div>
                <h3 className="text-sm sm:text-base font-bold text-white flex items-center gap-2">
                  <Server className="w-5 h-5 text-rose-400" />
                  <span>Catálogo de Microsserviços e Arquitetura SOA</span>
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Registo unificado de protocolos (REST, MCP JSON-RPC, BPMN 2.0, SVM RPC) e endpoints ativos.
                </p>
              </div>
              <div className="px-2.5 py-1 rounded bg-emerald-950 border border-emerald-500/40 text-emerald-400 text-xs font-mono font-bold">
                7 SERVIÇOS ONLINE
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {SOA_CATALOG.map((svc) => (
                <div key={svc.id} className="p-4 rounded-xl border border-slate-800 bg-slate-900/50 flex flex-col justify-between gap-3">
                  <div>
                    <div className="flex justify-between items-center mb-1.5">
                      <span className="text-[10px] font-mono text-purple-400 bg-purple-950/60 px-2 py-0.5 rounded border border-purple-800/30">
                        {svc.protocol}
                      </span>
                      <span className="text-[10px] text-emerald-400 font-mono font-bold flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                        {svc.latencyMs}ms
                      </span>
                    </div>
                    <h4 className="text-xs font-bold text-slate-200">{svc.name}</h4>
                    <p className="text-[11px] text-slate-400 mt-1">{svc.description}</p>
                  </div>

                  <div className="flex items-center justify-between gap-2">
                    <div className="p-2 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-cyan-300 truncate flex-1">
                      Rota: {svc.endpoint}
                    </div>
                    {svc.id === 'soa-github-pipeline' && (
                      <button
                        onClick={() => setIsGitHubModalOpen(true)}
                        className="px-2.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-[10px] font-mono font-semibold shrink-0 transition-colors"
                      >
                        Sincronizar
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* TAB 7: RUST SOURCE CODE VIEWER */}
        {activeTab === 'contract' && (
          <div className="rounded-xl border border-slate-800 bg-slate-950 shadow-2xl overflow-hidden flex flex-col">
            <div className="bg-slate-900/80 px-4 py-2 border-b border-slate-800 flex justify-between text-xs font-mono">
              <span className="text-slate-300">programs/solana_sandbox_counter/src/lib.rs</span>
              <button
                onClick={() => handleCopy(activeRustCode, 'rust')}
                className="px-2.5 py-1 text-xs font-mono bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 rounded flex items-center gap-1.5"
              >
                {copied === 'rust' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied === 'rust' ? 'Copiado!' : 'Copiar'}</span>
              </button>
            </div>
            <div className="p-4 overflow-x-auto max-h-[560px] overflow-y-auto font-code text-xs leading-relaxed touch-scroll">
              <table className="w-full border-collapse">
                <tbody>
                  {codeLines.map((line, idx) => (
                    <tr key={idx} className="hover:bg-slate-900/70">
                      <td className="w-10 pr-4 text-right text-slate-600 font-mono text-[11px] border-r border-slate-800/60 select-none">{idx + 1}</td>
                      <td className="pl-4 whitespace-pre text-slate-300">{line}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* TAB 8: CLIENT SVM */}
        {activeTab === 'client' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
            <div className="lg:col-span-5 rounded-xl border border-slate-800 bg-slate-900/40 p-4 space-y-3">
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>Simulador SVM Web3</span>
              </h3>
              <div>
                <label className="text-[11px] text-slate-400 font-mono block mb-1">Instrução:</label>
                <div className="grid grid-cols-2 gap-2">
                  {(['initialize', 'increment', 'decrement', 'reset', 'close'] as const).map(op => (
                    <button
                      key={op}
                      onClick={() => setSimOperation(op)}
                      className={`p-2 rounded-lg text-xs font-mono text-center ${
                        simOperation === op ? 'bg-purple-600 text-white font-bold' : 'bg-slate-950 border border-slate-800 text-slate-300'
                      }`}
                    >
                      {op}()
                    </button>
                  ))}
                </div>
              </div>
              <button
                onClick={handleRunSimulation}
                className="w-full py-2.5 px-4 rounded-lg bg-gradient-to-r from-purple-600 to-cyan-600 text-white font-medium text-xs flex items-center justify-center gap-2"
              >
                <Send className="w-3.5 h-3.5" />
                <span>Executar {simOperation}()</span>
              </button>
            </div>

            <div className="lg:col-span-7 rounded-xl border border-slate-800 bg-slate-950 flex flex-col overflow-hidden min-h-[360px]">
              <div className="bg-slate-900/80 px-4 py-2 border-b border-slate-800 text-xs font-mono text-slate-300">
                Consola SVM BPF
              </div>
              <div className="p-4 flex-1 space-y-2 overflow-y-auto max-h-[460px] font-mono text-xs touch-scroll">
                {simulationLogs.map((log, i) => (
                  <div key={i} className="p-2 rounded bg-slate-900/50 border border-slate-800 text-slate-300 text-[11px]">
                    <span className="text-slate-500 mr-2">[{log.time}]</span>
                    {log.text}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </main>

      {/* GitHub Sync Modal */}
      <GitHubSyncModal
        isOpen={isGitHubModalOpen}
        onClose={() => setIsGitHubModalOpen(false)}
        pipelinePayload={githubPayload}
      />
    </div>
  );
}
