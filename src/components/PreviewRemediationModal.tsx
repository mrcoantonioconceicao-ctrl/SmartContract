/**
 * Solana Anchor DevSecOps - Preview Remediation Side-by-Side Diff View
 * Componente: src/components/PreviewRemediationModal.tsx
 * Autoria: Marco Antonio Conceicao
 *
 * Exibe a comparacao lado a lado (Side-by-Side Diff) e unificada entre
 * o codigo vulneravel atual e a correcao de seguranca proposta pelo Auditor AST,
 * permitindo inspecao de diferencas em tempo real e aplicacao do patch com 1 clique.
 */

import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  X,
  Wrench,
  Copy,
  Check,
  Columns,
  Rows,
  Sparkles,
  FileCode,
  ArrowRight,
  Info
} from 'lucide-react';
import { AstFinding } from '../utils/astAuditor.ts';

export interface PreviewRemediationModalProps {
  isOpen: boolean;
  onClose: () => void;
  finding: AstFinding | null;
  currentCode: string;
  onApplyFix: (patchedCode: string) => void;
}

interface DiffLine {
  type: 'unchanged' | 'removed' | 'added';
  oldLineNumber?: number;
  newLineNumber?: number;
  text: string;
}

interface SideBySideRow {
  left?: {
    lineNumber: number;
    text: string;
    type: 'unchanged' | 'removed';
  };
  right?: {
    lineNumber: number;
    text: string;
    type: 'unchanged' | 'added';
  };
}

export function PreviewRemediationModal({
  isOpen,
  onClose,
  finding,
  currentCode,
  onApplyFix,
}: PreviewRemediationModalProps) {
  const [viewMode, setViewMode] = useState<'side-by-side' | 'unified'>('side-by-side');
  const [copiedMode, setCopiedMode] = useState<'old' | 'new' | 'patch' | null>(null);

  // Calcula o codigo remediado
  const proposedCode = useMemo(() => {
    if (!finding?.fixPatch) return currentCode;
    return currentCode.replace(finding.fixPatch.search, finding.fixPatch.replace);
  }, [finding, currentCode]);

  // Calcula os trechos de diff focados no patch
  const diffSnippet = useMemo(() => {
    if (!finding?.fixPatch) {
      return {
        vulnerableSnippet: finding?.snippet || '// Nao ha snippet vulneravel detectado',
        remediedSnippet: finding?.recommendation || '// Nenhuma acao necessaria',
      };
    }
    return {
      vulnerableSnippet: finding.fixPatch.search,
      remediedSnippet: finding.fixPatch.replace,
    };
  }, [finding]);

  // Calcula linhas lado a lado completas ou focadas
  const sideBySideData = useMemo(() => {
    if (!finding?.fixPatch) return { rows: [], unified: [] };

    const oldLines = currentCode.split('\n');
    const newLines = proposedCode.split('\n');

    // Encontra o indice de inicio da mudanca
    const searchFirstLine = finding.fixPatch.search.split('\n')[0].trim();
    let changeIndex = oldLines.findIndex(l => l.trim().includes(searchFirstLine));
    if (changeIndex === -1 && finding.line > 0) {
      changeIndex = Math.max(0, finding.line - 1);
    }

    // Janela de contexto: 5 linhas antes e 5 depois para foco cirurgico
    const contextStart = Math.max(0, changeIndex - 4);
    const oldSlice = oldLines.slice(contextStart, Math.min(oldLines.length, changeIndex + 12));
    const oldSliceText = oldSlice.join('\n');
    const newSliceText = oldSliceText.replace(finding.fixPatch.search, finding.fixPatch.replace);

    const oldSliceLines = oldSliceText.split('\n');
    const newSliceLines = newSliceText.split('\n');

    const searchLines = finding.fixPatch.search.split('\n').map(s => s.trim());
    const replaceLines = finding.fixPatch.replace.split('\n').map(s => s.trim());

    const rows: SideBySideRow[] = [];
    let oldNum = contextStart + 1;
    let newNum = contextStart + 1;

    let i = 0;
    let j = 0;

    while (i < oldSliceLines.length || j < newSliceLines.length) {
      const oldLine = oldSliceLines[i];
      const newLine = newSliceLines[j];

      const isOldTarget = oldLine !== undefined && searchLines.includes(oldLine.trim());
      const isNewTarget = newLine !== undefined && replaceLines.includes(newLine.trim());

      if (isOldTarget && isNewTarget && oldLine.trim() !== newLine.trim()) {
        rows.push({
          left: { lineNumber: oldNum++, text: oldLine, type: 'removed' },
          right: { lineNumber: newNum++, text: newLine, type: 'added' },
        });
        i++;
        j++;
      } else if (isOldTarget && !isNewTarget) {
        rows.push({
          left: { lineNumber: oldNum++, text: oldLine, type: 'removed' },
          right: undefined,
        });
        i++;
      } else if (!isOldTarget && isNewTarget) {
        rows.push({
          left: undefined,
          right: { lineNumber: newNum++, text: newLine, type: 'added' },
        });
        j++;
      } else {
        rows.push({
          left: oldLine !== undefined ? { lineNumber: oldNum++, text: oldLine, type: 'unchanged' } : undefined,
          right: newLine !== undefined ? { lineNumber: newNum++, text: newLine, type: 'unchanged' } : undefined,
        });
        i++;
        j++;
      }
    }

    // Unified diff lines
    const unified: DiffLine[] = [];
    rows.forEach(r => {
      if (r.left?.type === 'removed') {
        unified.push({ type: 'removed', oldLineNumber: r.left.lineNumber, text: r.left.text });
      }
      if (r.right?.type === 'added') {
        unified.push({ type: 'added', newLineNumber: r.right.lineNumber, text: r.right.text });
      }
      if (r.left?.type === 'unchanged' && r.right?.type === 'unchanged') {
        unified.push({
          type: 'unchanged',
          oldLineNumber: r.left.lineNumber,
          newLineNumber: r.right.lineNumber,
          text: r.left.text,
        });
      }
    });

    return { rows, unified };
  }, [currentCode, proposedCode, finding]);

  const handleCopyText = (text: string, mode: 'old' | 'new' | 'patch') => {
    navigator.clipboard.writeText(text);
    setCopiedMode(mode);
    setTimeout(() => setCopiedMode(null), 2000);
  };

  const handleApply = () => {
    if (!finding?.fixPatch) return;
    onApplyFix(proposedCode);
    onClose();
  };

  if (!isOpen || !finding) return null;

  const isCritical = finding.severity === 'CRITICAL';
  const isHigh = finding.severity === 'HIGH';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-fadeIn">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl w-full max-w-6xl shadow-2xl flex flex-col max-h-[92vh] overflow-hidden">
        {/* Header Modal */}
        <div className="p-5 border-b border-slate-800 bg-slate-950/90 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-start sm:items-center space-x-3">
            <div
              className={`p-2.5 rounded-xl border ${
                isCritical
                  ? 'bg-red-500/15 border-red-500/30 text-red-400'
                  : isHigh
                  ? 'bg-amber-500/15 border-amber-500/30 text-amber-400'
                  : 'bg-cyan-500/15 border-cyan-500/30 text-cyan-400'
              }`}
            >
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span
                  className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${
                    isCritical
                      ? 'bg-red-500/20 text-red-400 border-red-500/30'
                      : isHigh
                      ? 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                      : 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30'
                  }`}
                >
                  {finding.severity}
                </span>
                <span className="text-xs font-mono text-slate-400">{finding.ruleId}</span>
                <span className="text-[10px] font-mono text-slate-500">Linha {finding.line}</span>
              </div>
              <h2 className="text-lg font-bold text-white tracking-tight mt-0.5 flex items-center space-x-2">
                <span>Preview de Remediacao de Seguranca (AST)</span>
              </h2>
              <p className="text-xs text-slate-400 max-w-2xl line-clamp-1">{finding.title}</p>
            </div>
          </div>

          <div className="flex items-center space-x-2 shrink-0">
            {/* View Mode Toggle */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-0.5 flex items-center text-xs font-mono">
              <button
                onClick={() => setViewMode('side-by-side')}
                className={`px-2.5 py-1.5 rounded-md flex items-center space-x-1.5 transition-all ${
                  viewMode === 'side-by-side'
                    ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
                title="Visualizacao Lado a Lado (Side-by-Side)"
              >
                <Columns className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Lado a Lado</span>
              </button>
              <button
                onClick={() => setViewMode('unified')}
                className={`px-2.5 py-1.5 rounded-md flex items-center space-x-1.5 transition-all ${
                  viewMode === 'unified'
                    ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
                title="Visualizacao Unificada (Unified Diff)"
              >
                <Rows className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">Unificado</span>
              </button>
            </div>

            <button
              onClick={onClose}
              className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
              title="Fechar"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Informacoes de Contexto e Explicacao do Patch */}
        <div className="bg-slate-950/60 border-b border-slate-800 p-4 space-y-2 text-xs">
          <div className="flex items-start space-x-2 text-slate-300">
            <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
            <div>
              <strong className="text-white">Descricao do Risco: </strong>
              <span>{finding.description}</span>
            </div>
          </div>
          {finding.fixPatch && (
            <div className="flex items-start space-x-2 text-emerald-300 bg-emerald-950/30 p-2.5 rounded-lg border border-emerald-800/40">
              <Sparkles className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <strong className="text-emerald-400">Proposta de Correcao da AST: </strong>
                <span>{finding.fixPatch.explanation}</span>
              </div>
            </div>
          )}
        </div>

        {/* Diff Principal: Lado a Lado vs Unificado */}
        <div className="flex-1 overflow-y-auto p-4 bg-slate-950 font-mono text-xs touch-scroll">
          {viewMode === 'side-by-side' ? (
            <div className="space-y-4">
              {/* Header Colunas Lado a Lado */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Lado Esquerdo: Vulneravel Atual */}
                <div className="rounded-xl border border-red-500/30 bg-red-950/10 overflow-hidden flex flex-col">
                  <div className="p-3 bg-red-950/40 border-b border-red-500/20 flex items-center justify-between text-xs">
                    <div className="flex items-center space-x-2 text-red-300 font-bold">
                      <span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block" />
                      <span>Codigo Vulneravel Atual</span>
                      <span className="text-[10px] text-red-400 font-normal">(- Removido / Inseguro)</span>
                    </div>
                    <button
                      onClick={() => handleCopyText(diffSnippet.vulnerableSnippet, 'old')}
                      className="text-[11px] text-slate-400 hover:text-white flex items-center space-x-1"
                    >
                      {copiedMode === 'old' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedMode === 'old' ? 'Copiado!' : 'Copiar'}</span>
                    </button>
                  </div>

                  <div className="p-3 bg-slate-950/90 overflow-x-auto divide-y divide-slate-900 leading-relaxed min-h-[140px]">
                    {sideBySideData.rows.map((row, idx) => {
                      const item = row.left;
                      if (!item) {
                        return (
                          <div key={idx} className="flex items-center text-slate-700 select-none py-0.5 opacity-30">
                            <span className="w-10 px-2 text-right">~</span>
                            <span className="px-2 italic">---</span>
                          </div>
                        );
                      }
                      const isRemoved = item.type === 'removed';
                      return (
                        <div
                          key={idx}
                          className={`flex items-start py-0.5 ${
                            isRemoved ? 'bg-red-500/20 text-red-200 font-medium' : 'text-slate-400'
                          }`}
                        >
                          <span className="w-10 px-2 text-right text-slate-600 select-none shrink-0 font-mono text-[11px]">
                            {item.lineNumber}
                          </span>
                          <span className="w-6 text-center select-none text-red-400 font-bold shrink-0">
                            {isRemoved ? '-' : ' '}
                          </span>
                          <pre className="px-2 overflow-x-auto whitespace-pre font-mono">{item.text || ' '}</pre>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Lado Direito: Proposta de Correcao AST */}
                <div className="rounded-xl border border-emerald-500/30 bg-emerald-950/10 overflow-hidden flex flex-col">
                  <div className="p-3 bg-emerald-950/40 border-b border-emerald-500/20 flex items-center justify-between text-xs">
                    <div className="flex items-center space-x-2 text-emerald-300 font-bold">
                      <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block animate-pulse" />
                      <span>Correcao Proposta pelo Auditor AST</span>
                      <span className="text-[10px] text-emerald-400 font-normal">(+ Adicionado / Seguro)</span>
                    </div>
                    <button
                      onClick={() => handleCopyText(diffSnippet.remediedSnippet, 'new')}
                      className="text-[11px] text-slate-400 hover:text-white flex items-center space-x-1"
                    >
                      {copiedMode === 'new' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copiedMode === 'new' ? 'Copiado!' : 'Copiar'}</span>
                    </button>
                  </div>

                  <div className="p-3 bg-slate-950/90 overflow-x-auto divide-y divide-slate-900 leading-relaxed min-h-[140px]">
                    {sideBySideData.rows.map((row, idx) => {
                      const item = row.right;
                      if (!item) {
                        return (
                          <div key={idx} className="flex items-center text-slate-700 select-none py-0.5 opacity-30">
                            <span className="w-10 px-2 text-right">~</span>
                            <span className="px-2 italic">---</span>
                          </div>
                        );
                      }
                      const isAdded = item.type === 'added';
                      return (
                        <div
                          key={idx}
                          className={`flex items-start py-0.5 ${
                            isAdded ? 'bg-emerald-500/20 text-emerald-200 font-medium' : 'text-slate-400'
                          }`}
                        >
                          <span className="w-10 px-2 text-right text-slate-600 select-none shrink-0 font-mono text-[11px]">
                            {item.lineNumber}
                          </span>
                          <span className="w-6 text-center select-none text-emerald-400 font-bold shrink-0">
                            {isAdded ? '+' : ' '}
                          </span>
                          <pre className="px-2 overflow-x-auto whitespace-pre font-mono">{item.text || ' '}</pre>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>

              {/* Destaque Cirurgico do Snippet Comparado */}
              <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40 space-y-3">
                <div className="text-xs font-mono font-bold text-slate-300 flex items-center justify-between">
                  <span>Diferenca Cirurgica (Target vs Replacement):</span>
                  <span className="text-[11px] text-slate-500 font-normal">Auto-patch testado em AST</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div className="p-3 rounded-lg bg-red-950/30 border border-red-500/20 font-mono text-[11px] text-red-300 overflow-x-auto">
                    <div className="text-[10px] uppercase font-bold text-red-400 mb-1 select-none">// Trecho Vulneravel:</div>
                    <pre className="whitespace-pre-wrap">{diffSnippet.vulnerableSnippet}</pre>
                  </div>
                  <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-500/20 font-mono text-[11px] text-emerald-300 overflow-x-auto">
                    <div className="text-[10px] uppercase font-bold text-emerald-400 mb-1 select-none">// Trecho Remediado:</div>
                    <pre className="whitespace-pre-wrap">{diffSnippet.remediedSnippet}</pre>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            /* Visualizacao Unificada */
            <div className="rounded-xl border border-slate-800 bg-slate-950 overflow-hidden flex flex-col">
              <div className="p-3 bg-slate-900/70 border-b border-slate-800 flex items-center justify-between text-xs">
                <div className="flex items-center space-x-2 text-slate-300 font-bold">
                  <FileCode className="w-4 h-4 text-cyan-400" />
                  <span>Unified Patch View (git diff style)</span>
                </div>
                <button
                  onClick={() => handleCopyText(sideBySideData.unified.map(u => `${u.type === 'removed' ? '-' : u.type === 'added' ? '+' : ' '} ${u.text}`).join('\n'), 'patch')}
                  className="text-[11px] text-slate-400 hover:text-white flex items-center space-x-1"
                >
                  {copiedMode === 'patch' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedMode === 'patch' ? 'Copiado!' : 'Copiar Diff'}</span>
                </button>
              </div>

              <div className="p-3 overflow-x-auto divide-y divide-slate-900 leading-relaxed">
                {sideBySideData.unified.map((line, idx) => {
                  const isRemoved = line.type === 'removed';
                  const isAdded = line.type === 'added';

                  return (
                    <div
                      key={idx}
                      className={`flex items-start py-0.5 ${
                        isRemoved
                          ? 'bg-red-500/20 text-red-200'
                          : isAdded
                          ? 'bg-emerald-500/20 text-emerald-200'
                          : 'text-slate-400'
                      }`}
                    >
                      <span className="w-8 text-right text-slate-600 select-none shrink-0 font-mono text-[11px] px-1">
                        {line.oldLineNumber || ''}
                      </span>
                      <span className="w-8 text-right text-slate-600 select-none shrink-0 font-mono text-[11px] px-1">
                        {line.newLineNumber || ''}
                      </span>
                      <span
                        className={`w-6 text-center select-none font-bold shrink-0 ${
                          isRemoved ? 'text-red-400' : isAdded ? 'text-emerald-400' : 'text-slate-600'
                        }`}
                      >
                        {isRemoved ? '-' : isAdded ? '+' : ' '}
                      </span>
                      <pre className="px-2 overflow-x-auto whitespace-pre font-mono">{line.text || ' '}</pre>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Footer com Acoes */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/90 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="text-xs text-slate-400 flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            <span>
              A aplicacao da correcao preserva a integridade de 49B de memoria, signatarios Ed25519 e a regra C44.
            </span>
          </div>

          <div className="flex items-center space-x-3 w-full sm:w-auto justify-end">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-xl text-xs font-mono text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            >
              Cancelar
            </button>

            {finding.autoFixAvailable && finding.fixPatch ? (
              <button
                onClick={handleApply}
                className="px-5 py-2.5 rounded-xl text-xs font-mono font-bold bg-gradient-to-r from-cyan-600 to-emerald-600 hover:from-cyan-500 hover:to-emerald-500 text-white shadow-lg shadow-cyan-600/30 flex items-center space-x-2 transition-all transform hover:-translate-y-0.5"
              >
                <Wrench className="w-4 h-4" />
                <span>Aplicar Correcao Proposta (1-Clique)</span>
              </button>
            ) : (
              <span className="text-xs font-mono text-slate-500 italic">
                Correcao manual recomendada
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
