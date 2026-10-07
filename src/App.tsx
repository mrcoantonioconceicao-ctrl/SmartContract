/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { 
  ShieldCheck, 
  Terminal, 
  Cpu, 
  Code2, 
  CheckCircle2, 
  AlertTriangle, 
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
  Send, 
  Plus, 
  Trash2, 
  Sparkles,
  ExternalLink,
  Workflow
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

export default function App() {
  const [activeTab, setActiveTab] = useState<'contract' | 'client' | 'generator' | 'pipeline'>('contract');
  const [copied, setCopied] = useState<string | null>(null);

  // Client Simulator State
  const [authorityInput, setAuthorityInput] = useState<string>('9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM');
  const [simOperation, setSimOperation] = useState<'initialize' | 'increment' | 'decrement' | 'reset' | 'close'>('increment');
  const [simAmount, setSimAmount] = useState<number>(1);
  const [simulatedCount, setSimulatedCount] = useState<number>(10);
  const [simulationLogs, setSimulationLogs] = useState<string[]>([
    'Client initialized with Program ID: CntSandbox111111111111111111111111111111111',
    'Derived PDA: 4p5Y7d... (Seed: [b"counter", authority]) with Bump: 254',
    'Rent-Exempt Balance Verified: 1,231,920 Lamports for 49 bytes exact allocation',
  ]);

  // Dynamic Generator State
  const [generatorConfig, setGeneratorConfig] = useState<ContractTemplateConfig>(DEFAULT_COUNTER_CONFIG);
  const [generatedRustCode, setGeneratedRustCode] = useState<string>(() => generateModularAnchorContract(DEFAULT_COUNTER_CONFIG));
  const [newFieldName, setNewFieldName] = useState('');
  const [newFieldType, setNewFieldType] = useState<'u64' | 'u32' | 'u8' | 'Pubkey' | 'bool'>('u64');

  // Copy helper
  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  // Run Client Simulation
  const handleRunSimulation = () => {
    let nextCount = simulatedCount;
    let logMsg = '';

    if (simOperation === 'initialize') {
      nextCount = simAmount;
      logMsg = `[OK] initialize() executed -> Initialized UserCounter with initial_count = ${simAmount}. Space = 49 bytes.`;
    } else if (simOperation === 'increment') {
      nextCount = simulatedCount + simAmount;
      logMsg = `[OK] increment(${simAmount}) executed -> .checked_add(${simAmount}) success. New Count = ${nextCount}. Signer verified.`;
    } else if (simOperation === 'decrement') {
      if (simulatedCount < simAmount) {
        logMsg = `[FAIL] SecurityErrorCode::NumericalUnderflow -> Count ${simulatedCount} cannot be subtracted by ${simAmount}. Transaction rejected safely.`;
      } else {
        nextCount = simulatedCount - simAmount;
        logMsg = `[OK] decrement(${simAmount}) executed -> .checked_sub(${simAmount}) success. New Count = ${nextCount}. Signer verified.`;
      }
    } else if (simOperation === 'reset') {
      nextCount = 0;
      logMsg = `[OK] reset() executed -> State reset to zero by authority. has_one = authority verified.`;
    } else if (simOperation === 'close') {
      nextCount = 0;
      logMsg = `[OK] close() executed -> PDA account closed. 1,231,920 lamports refunded to ${authorityInput.slice(0, 8)}...`;
    }

    setSimulatedCount(nextCount);
    setSimulationLogs(prev => [logMsg, ...prev.slice(0, 8)]);
  };

  // Add field in generator
  const handleAddField = () => {
    if (!newFieldName.trim()) return;
    const sizeMap: Record<string, number> = {
      u64: 8,
      u32: 4,
      u8: 1,
      Pubkey: 32,
      bool: 1,
    };
    const updatedFields: CustomField[] = [
      ...generatorConfig.fields,
      {
        name: newFieldName.trim().toLowerCase(),
        rustType: newFieldType,
        sizeBytes: sizeMap[newFieldType] || 8,
        description: `Custom ${newFieldType} state parameter`,
      },
    ];

    const updatedConfig = { ...generatorConfig, fields: updatedFields };
    setGeneratorConfig(updatedConfig);
    setGeneratedRustCode(generateModularAnchorContract(updatedConfig));
    setNewFieldName('');
  };

  // Remove field in generator
  const handleRemoveField = (index: number) => {
    if (generatorConfig.fields[index].name === 'authority' || generatorConfig.fields[index].name === 'bump') {
      return; // protect mandatory security fields
    }
    const updatedFields = generatorConfig.fields.filter((_, idx) => idx !== index);
    const updatedConfig = { ...generatorConfig, fields: updatedFields };
    setGeneratorConfig(updatedConfig);
    setGeneratedRustCode(generateModularAnchorContract(updatedConfig));
  };

  const codeLines = RUST_CONTRACT_SOURCE.trim().split('\n');
  const spaceInfo = calculateAccountSpace(generatorConfig.fields);
  const githubPayload = generateGitHubPipelinePayload({ customRustCode: generatedRustCode });

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top IDE Header */}
      <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur px-5 py-3 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-tr from-purple-600 via-indigo-600 to-cyan-500 p-0.5 shadow-lg shadow-purple-500/20">
            <div className="w-full h-full bg-slate-950 rounded-[7px] flex items-center justify-center">
              <ShieldCheck className="w-5 h-5 text-cyan-400" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-semibold tracking-wide text-white">
                Solana Anchor DevSecOps IDE
              </h1>
              <span className="px-2 py-0.5 text-[10px] uppercase font-bold tracking-wider bg-purple-500/10 text-purple-400 border border-purple-500/30 rounded">
                Stage 3: Contract Generator & Client
              </span>
            </div>
            <p className="text-xs text-slate-400 font-mono">
              Rust Model • TS Client • Rent-Exempt 49B • GitHub Pipeline
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300">
            <Key className="w-3.5 h-3.5 text-amber-400" />
            <span className="text-slate-400 text-[11px]">ID:</span>
            <span className="text-amber-300 text-[11px] font-semibold">{PROGRAM_ID.slice(0, 10)}...{PROGRAM_ID.slice(-6)}</span>
          </div>
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-emerald-950/40 border border-emerald-500/30 text-emerald-400 text-xs font-mono">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            DevSecOps: Verified
          </div>
        </div>
      </header>

      {/* Main Workspace Area */}
      <main className="flex-1 p-4 md:p-6 max-w-7xl w-full mx-auto flex flex-col gap-5">
        {/* Navigation Tabs */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-2">
          <div className="flex items-center gap-2 overflow-x-auto">
            <button
              onClick={() => setActiveTab('contract')}
              className={`px-3.5 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center gap-2 shrink-0 ${
                activeTab === 'contract'
                  ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              <Code2 className="w-3.5 h-3.5" />
              1. Modelo Rust Anchor (lib.rs)
            </button>
            <button
              onClick={() => setActiveTab('client')}
              className={`px-3.5 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center gap-2 shrink-0 ${
                activeTab === 'client'
                  ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              2. Cliente TypeScript (client/index.ts)
            </button>
            <button
              onClick={() => setActiveTab('generator')}
              className={`px-3.5 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center gap-2 shrink-0 ${
                activeTab === 'generator'
                  ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5" />
              3. Gerador de Contratos Customizados
            </button>
            <button
              onClick={() => setActiveTab('pipeline')}
              className={`px-3.5 py-1.5 text-xs font-medium rounded-lg transition-all flex items-center gap-2 shrink-0 ${
                activeTab === 'pipeline'
                  ? 'bg-purple-600 text-white shadow-md shadow-purple-600/30'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              <GitPullRequest className="w-3.5 h-3.5" />
              4. Pipeline GitHub & PR Atómico
            </button>
          </div>
        </div>

        {/* TAB 1: RUST CONTRACT SOURCE */}
        {activeTab === 'contract' && (
          <div className="flex flex-col gap-4">
            {/* Quick Guarantees bar */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/40 flex items-center gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span className="text-xs text-slate-300">PDA Determinístico: <code className="text-cyan-300">[b"counter", authority]</code></span>
              </div>
              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/40 flex items-center gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span className="text-xs text-slate-300">Rent-Exempt: <strong className="text-emerald-300">49 Bytes</strong></span>
              </div>
              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/40 flex items-center gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span className="text-xs text-slate-300">Checked Math: <code className="text-amber-300">checked_add/sub</code></span>
              </div>
              <div className="p-3 rounded-lg border border-slate-800 bg-slate-900/40 flex items-center gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span className="text-xs text-slate-300">Controlo de Acesso: <code className="text-purple-300">has_one = authority</code></span>
              </div>
            </div>

            {/* Code Viewer */}
            <div className="rounded-xl border border-slate-800 bg-slate-950 shadow-2xl overflow-hidden flex flex-col">
              <div className="bg-slate-900/80 px-4 py-2 border-b border-slate-800 flex items-center justify-between text-xs font-mono">
                <div className="flex items-center gap-2 text-slate-300">
                  <FileCode className="w-4 h-4 text-orange-400" />
                  <span>programs/solana_sandbox_counter/src/lib.rs</span>
                </div>
                <button
                  onClick={() => handleCopy(RUST_CONTRACT_SOURCE, 'rust')}
                  className="px-2.5 py-1 text-xs font-mono bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 rounded flex items-center gap-1.5 transition-colors"
                >
                  {copied === 'rust' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied === 'rust' ? 'Copiado!' : 'Copiar Código'}</span>
                </button>
              </div>

              <div className="p-4 overflow-x-auto max-h-[560px] overflow-y-auto font-code text-xs leading-relaxed">
                <table className="w-full border-collapse">
                  <tbody>
                    {codeLines.map((line, idx) => {
                      const lineNum = idx + 1;
                      const isHighlight = 
                        line.includes('declare_id!') ||
                        line.includes('checked_add') ||
                        line.includes('checked_sub') ||
                        line.includes('has_one = authority') ||
                        line.includes('seeds = [b"counter"') ||
                        line.includes('ACCOUNT_SPACE');

                      return (
                        <tr key={lineNum} className={`hover:bg-slate-900/70 ${isHighlight ? 'bg-purple-950/20' : ''}`}>
                          <td className="w-10 pr-4 text-right select-none text-slate-600 font-mono text-[11px] border-r border-slate-800/60">
                            {lineNum}
                          </td>
                          <td className="pl-4 whitespace-pre text-slate-300">
                            {line.startsWith('//') || line.startsWith('///') ? (
                              <span className="text-slate-500 italic">{line}</span>
                            ) : line.includes('declare_id!') ? (
                              <span className="text-cyan-400 font-semibold">{line}</span>
                            ) : line.includes('has_one = authority') ? (
                              <span className="text-amber-300 font-medium">{line}</span>
                            ) : line.includes('checked_add') || line.includes('checked_sub') ? (
                              <span className="text-emerald-300 font-semibold">{line}</span>
                            ) : (
                              line
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: TYPESCRIPT CLIENT INTERACTION & SIMULATION */}
        {activeTab === 'client' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {/* Control Panel */}
            <div className="lg:col-span-1 rounded-xl border border-slate-800 bg-slate-900/40 p-5 flex flex-col gap-4">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  Simulador de Interação Web3 (Anchor)
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Executa métodos do cliente TypeScript (<code className="text-slate-300">client/index.ts</code>) com derivação determinística de PDA e verificações prévias.
                </p>
              </div>

              <div className="space-y-3">
                <div>
                  <label className="text-[11px] text-slate-400 font-mono">Autoridade (Wallet Pubkey):</label>
                  <input
                    type="text"
                    value={authorityInput}
                    onChange={(e) => setAuthorityInput(e.target.value)}
                    className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                <div>
                  <label className="text-[11px] text-slate-400 font-mono">Instrução a Executar:</label>
                  <div className="grid grid-cols-2 gap-2 mt-1">
                    {(['initialize', 'increment', 'decrement', 'reset', 'close'] as const).map(op => (
                      <button
                        key={op}
                        onClick={() => setSimOperation(op)}
                        className={`px-2.5 py-1.5 text-xs font-mono rounded-lg transition-all capitalize text-left ${
                          simOperation === op
                            ? 'bg-purple-600 text-white font-semibold'
                            : 'bg-slate-950 border border-slate-800 text-slate-300 hover:bg-slate-900'
                        }`}
                      >
                        {op}()
                      </button>
                    ))}
                  </div>
                </div>

                {(simOperation === 'increment' || simOperation === 'decrement' || simOperation === 'initialize') && (
                  <div>
                    <label className="text-[11px] text-slate-400 font-mono">Quantidade (amount):</label>
                    <input
                      type="number"
                      min="1"
                      value={simAmount}
                      onChange={(e) => setSimAmount(Math.max(1, parseInt(e.target.value) || 1))}
                      className="w-full mt-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-amber-300 focus:outline-none focus:border-amber-500"
                    />
                  </div>
                )}

                <button
                  onClick={handleRunSimulation}
                  className="w-full mt-2 py-2.5 px-4 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-medium text-xs flex items-center justify-center gap-2 shadow-lg shadow-purple-600/30 transition-all"
                >
                  <Send className="w-3.5 h-3.5" />
                  Executar Instrução no Sandbox
                </button>
              </div>

              {/* Status State Widget */}
              <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between mt-auto">
                <div>
                  <span className="text-[11px] text-slate-400">Estado Atual do Contador:</span>
                  <div className="text-xl font-bold font-mono text-cyan-400">{simulatedCount}</div>
                </div>
                <div className="text-right">
                  <span className="text-[11px] text-slate-400">Rent-Exempt Lamports:</span>
                  <div className="text-xs font-mono text-emerald-400">1,231,920</div>
                </div>
              </div>
            </div>

            {/* Terminal Simulation Log */}
            <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-950 flex flex-col overflow-hidden">
              <div className="bg-slate-900/80 px-4 py-2 border-b border-slate-800 flex items-center justify-between text-xs font-mono">
                <div className="flex items-center gap-2 text-slate-300">
                  <Terminal className="w-4 h-4 text-emerald-400" />
                  <span>Solana Sandbox Execution Logs</span>
                </div>
                <span className="text-[11px] text-slate-500">RPC: devnet simulation</span>
              </div>

              <div className="p-4 flex-1 flex flex-col justify-end font-mono text-xs space-y-2 overflow-y-auto max-h-[460px]">
                {simulationLogs.map((log, index) => {
                  const isFail = log.includes('[FAIL]');
                  const isOk = log.includes('[OK]');
                  return (
                    <div 
                      key={index}
                      className={`p-2 rounded border leading-relaxed ${
                        isFail 
                          ? 'bg-rose-950/30 border-rose-800/40 text-rose-300' 
                          : isOk 
                          ? 'bg-emerald-950/20 border-emerald-800/30 text-emerald-300' 
                          : 'bg-slate-900/40 border-slate-800 text-slate-400'
                      }`}
                    >
                      <span className="text-slate-600 mr-2 text-[10px]">[{new Date().toLocaleTimeString()}]</span>
                      {log}
                    </div>
                  );
                })}
              </div>

              <div className="p-3 bg-slate-900/50 border-t border-slate-800 flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span>Instruções suportadas: Initialize, Increment, Decrement, Reset, Close</span>
                <span className="text-emerald-400">Checked Math: ACTIVE</span>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: DYNAMIC CONTRACT GENERATOR */}
        {activeTab === 'generator' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {/* Rules and Fields Config */}
            <div className="lg:col-span-1 rounded-xl border border-slate-800 bg-slate-900/40 p-5 flex flex-col gap-4">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-amber-400" />
                  Configuração de Regras de Negócio
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Adiciona campos de estado customizados. O compilador recalcula instantaneamente o tamanho exato de memória e gera o contrato Rust.
                </p>
              </div>

              {/* Add Field Input */}
              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="Nome do campo (ex: points, balance)"
                  value={newFieldName}
                  onChange={(e) => setNewFieldName(e.target.value)}
                  className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-purple-500"
                />
                <select
                  value={newFieldType}
                  onChange={(e) => setNewFieldType(e.target.value as any)}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-xs font-mono text-purple-300 focus:outline-none focus:border-purple-500"
                >
                  <option value="u64">u64 (8B)</option>
                  <option value="u32">u32 (4B)</option>
                  <option value="u8">u8 (1B)</option>
                  <option value="Pubkey">Pubkey (32B)</option>
                  <option value="bool">bool (1B)</option>
                </select>
                <button
                  onClick={handleAddField}
                  className="p-2 bg-purple-600 hover:bg-purple-500 rounded-lg text-white"
                  title="Adicionar Campo"
                >
                  <Plus className="w-4 h-4" />
                </button>
              </div>

              {/* Current Fields Table */}
              <div className="space-y-2 mt-2">
                <div className="text-[11px] font-mono text-slate-400">Campos do Estado da Conta:</div>
                <div className="space-y-1.5 max-h-56 overflow-y-auto">
                  {generatorConfig.fields.map((f, i) => {
                    const isProtected = f.name === 'authority' || f.name === 'bump';
                    return (
                      <div 
                        key={i} 
                        className="p-2 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-xs font-mono"
                      >
                        <div className="flex items-center gap-2">
                          <span className="text-cyan-300 font-medium">{f.name}</span>
                          <span className="text-slate-500">:</span>
                          <span className="text-purple-300">{f.rustType}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                            {f.sizeBytes} B
                          </span>
                          {!isProtected && (
                            <button
                              onClick={() => handleRemoveField(i)}
                              className="text-slate-500 hover:text-rose-400"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Memory summary */}
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1 text-xs font-mono mt-auto">
                <div className="flex justify-between text-slate-400">
                  <span>Discriminador Anchor:</span>
                  <span>8 Bytes</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Campos Definidos:</span>
                  <span>{spaceInfo.fieldsBytes} Bytes</span>
                </div>
                <div className="flex justify-between text-emerald-400 font-bold border-t border-slate-800 pt-1">
                  <span>Espaço Total Exato:</span>
                  <span>{spaceInfo.totalBytes} Bytes</span>
                </div>
                <div className="flex justify-between text-amber-400 text-[11px] pt-1">
                  <span>Rent-Exempt Mínimo:</span>
                  <span>~{spaceInfo.rentExemptLamports.toLocaleString()} Lamports</span>
                </div>
              </div>
            </div>

            {/* Generated Rust Code Preview */}
            <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-950 flex flex-col overflow-hidden">
              <div className="bg-slate-900/80 px-4 py-2 border-b border-slate-800 flex items-center justify-between text-xs font-mono">
                <div className="flex items-center gap-2 text-slate-300">
                  <Code2 className="w-4 h-4 text-purple-400" />
                  <span>Contrato Rust Gerado Dinamicamente</span>
                </div>
                <button
                  onClick={() => handleCopy(generatedRustCode, 'generated')}
                  className="px-2.5 py-1 text-xs font-mono bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 rounded flex items-center gap-1.5 transition-colors"
                >
                  {copied === 'generated' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied === 'generated' ? 'Copiado!' : 'Copiar Rust'}</span>
                </button>
              </div>

              <div className="p-4 overflow-x-auto max-h-[560px] overflow-y-auto font-code text-xs leading-relaxed text-slate-300 whitespace-pre">
                {generatedRustCode}
              </div>
            </div>
          </div>
        )}

        {/* TAB 4: GITHUB PIPELINE & PR INTEGRATION */}
        {activeTab === 'pipeline' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {/* PR Details Card */}
            <div className="lg:col-span-1 rounded-xl border border-slate-800 bg-slate-900/40 p-5 flex flex-col gap-4">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <GitPullRequest className="w-4 h-4 text-emerald-400" />
                  Pull Request DevSecOps Gerado
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Carga útil atómica pronta para integração com a API do GitHub (Branches, Commits e Pull Request automático).
                </p>
              </div>

              <div className="space-y-3 font-mono text-xs">
                <div>
                  <span className="text-[11px] text-slate-400">Repositório Alvo:</span>
                  <div className="p-2 rounded bg-slate-950 border border-slate-800 text-cyan-300 mt-0.5">
                    {githubPayload.repository}
                  </div>
                </div>

                <div>
                  <span className="text-[11px] text-slate-400">Branch Atómica:</span>
                  <div className="p-2 rounded bg-slate-950 border border-slate-800 text-purple-300 mt-0.5 flex items-center gap-1.5">
                    <GitBranch className="w-3.5 h-3.5 text-purple-400" />
                    <span>{githubPayload.targetBranch}</span>
                  </div>
                </div>

                <div>
                  <span className="text-[11px] text-slate-400">Mensagem do Commit:</span>
                  <div className="p-2 rounded bg-slate-950 border border-slate-800 text-slate-300 mt-0.5 text-[11px] leading-relaxed">
                    {githubPayload.commit.message}
                  </div>
                </div>

                <div>
                  <span className="text-[11px] text-slate-400">Ficheiros no Commit Atómico ({githubPayload.commit.files.length}):</span>
                  <div className="space-y-1 mt-1">
                    {githubPayload.commit.files.map((file, idx) => (
                      <div key={idx} className="p-1.5 rounded bg-slate-950 border border-slate-800 text-[11px] text-slate-400 flex items-center gap-1.5">
                        <FileCode className="w-3 h-3 text-cyan-400 shrink-0" />
                        <span className="truncate">{file.path}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <button
                onClick={() => handleCopy(JSON.stringify(githubPayload, null, 2), 'payload')}
                className="w-full mt-auto py-2 px-3 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs flex items-center justify-center gap-2 shadow-lg shadow-emerald-600/20 transition-all"
              >
                {copied === 'payload' ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied === 'payload' ? 'Payload Copiado!' : 'Copiar JSON do Pipeline'}</span>
              </button>
            </div>

            {/* Pull Request Body & GitHub Actions Preview */}
            <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-950 flex flex-col overflow-hidden">
              <div className="bg-slate-900/80 px-4 py-2 border-b border-slate-800 flex items-center justify-between text-xs font-mono">
                <div className="flex items-center gap-2 text-slate-300">
                  <GitPullRequest className="w-4 h-4 text-emerald-400" />
                  <span>Pré-visualização do Pull Request & CI Workflow</span>
                </div>
                <div className="flex items-center gap-1.5">
                  {githubPayload.pullRequest.labels.map((l, i) => (
                    <span key={i} className="px-2 py-0.5 rounded-full text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                      {l}
                    </span>
                  ))}
                </div>
              </div>

              <div className="p-5 overflow-y-auto max-h-[560px] space-y-4">
                <div className="border-b border-slate-800 pb-3">
                  <h2 className="text-base font-bold text-white flex items-center gap-2">
                    {githubPayload.pullRequest.title}
                  </h2>
                  <div className="text-xs text-slate-400 mt-1">
                    Base: <span className="text-cyan-400 font-mono">main</span> ← Compare: <span className="text-purple-400 font-mono">{githubPayload.targetBranch}</span>
                  </div>
                </div>

                <div className="prose prose-invert max-w-none text-xs font-mono text-slate-300 whitespace-pre-wrap leading-relaxed bg-slate-900/50 p-4 rounded-lg border border-slate-800">
                  {githubPayload.pullRequest.body}
                </div>

                <div>
                  <div className="text-xs font-mono text-slate-400 mb-2 flex items-center gap-2">
                    <Workflow className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Workflow CI GitHub Actions (.github/workflows/anchor-devsecops-ci.yml):</span>
                  </div>
                  <pre className="p-3 bg-slate-900/70 rounded-lg border border-slate-800 font-mono text-[11px] text-cyan-300 overflow-x-auto leading-relaxed">
                    {githubPayload.commit.files.find(f => f.path.includes('workflows'))?.content}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
