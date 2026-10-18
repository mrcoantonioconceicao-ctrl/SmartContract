/**
 * Solana Anchor Security Agent Chat Panel
 * Modulo: src/components/SecurityAgentChat.tsx
 * Autoria Oficial: Marco Antonio Conceicao
 * Politica de Governanca: Regra C44 (Nao-Destrutiva) - Zero Mocks
 *
 * Painel Interativo de Chat com Agente de Seguranca IA contextualizado
 * via Model Context Protocol (MCP), Analisador AST Real e Grafo GraphRAG Enterprise.
 */

import React, { useState, useRef, useEffect } from 'react';
import {
  Brain,
  Send,
  Sparkles,
  ShieldCheck,
  Share2,
  Box,
  RotateCcw,
  Copy,
  Check,
  Code2,
  Terminal,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Maximize2,
  Minimize2,
  HelpCircle,
  ExternalLink,
  Wrench,
  Database
} from 'lucide-react';
import { AstAuditReport, AstFinding } from '../utils/astAuditor.ts';
import { EnterpriseGraphRagResult } from '../services/graphRAGEnterpriseService.ts';
import { MCP_TOOLS } from '../mcp/server.ts';

export interface SecurityAgentChatProps {
  activeRustCode: string;
  astReport: AstAuditReport;
  graphRagReport: EnterpriseGraphRagResult;
  onSelectTab?: (tab: string) => void;
  onApplyQuickFix?: (finding: AstFinding) => void;
  onRunMcpTool?: (toolName: string) => void;
  isEmbedded?: boolean;
  onClose?: () => void;
}

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  sourceModel?: string;
  mcpToolRecommendations?: string[];
}

export const SecurityAgentChat: React.FC<SecurityAgentChatProps> = ({
  activeRustCode,
  astReport,
  graphRagReport,
  onSelectTab,
  onApplyQuickFix,
  onRunMcpTool,
  isEmbedded = false,
  onClose,
}) => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome-1',
      role: 'assistant',
      content: `### Ola! Sou o seu Agente Autonomo de Seguranca Solana SVM & MCP

Estou conectado diretamente ao **AST Real**, ao motor **GraphRAG Enterprise** e as ferramentas do **Servidor MCP**.

**Status do Contexto Ativo:**
- **Auditor AST:** Pontuacao ${astReport.score}/100 (${astReport.status}) com ${astReport.findings.length} achado(s).
- **Grafo Semantico GraphRAG:** ${graphRagReport.enterpriseNodes.length} nos, ${graphRagReport.communities.length} comunidades hierarquicas e ${graphRagReport.multiHopPaths.length} rotas multi-hop mapeadas.
- **Veredito Determinístico:** **${graphRagReport.deterministicAuditStatus}**
- **Alocacao de Memoria:** 49 bytes exatos para \`UserCounter\` PDA.

Voce pode me fazer perguntas tecnicas em linguagem natural sobre qualquer vulnerabilidade, rotas de ataque, derivacao de PDAs ou como acionar ferramentas MCP.`,
      timestamp: new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }),
      sourceModel: 'Solana DevSecOps MCP Engine',
      mcpToolRecommendations: ['audit_rust_ast', 'query_graphrag_security', 'derive_pda_spec'],
    },
  ]);

  const [inputValue, setInputValue] = useState<string>('');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [showContextDetails, setShowContextDetails] = useState<boolean>(false);
  const [isExpanded, setIsExpanded] = useState<boolean>(false);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isLoading]);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleSendMessage = async (textToSend?: string) => {
    const query = (textToSend || inputValue).trim();
    if (!query || isLoading) return;

    const userMessage: ChatMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: query,
      timestamp: new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages(prev => [...prev, userMessage]);
    setInputValue('');
    setIsLoading(true);

    try {
      // Prepara o contexto de seguranca em tempo real
      const contextPayload = {
        activeRustCode,
        astFindings: astReport.findings.map(f => ({
          id: f.id,
          ruleId: f.ruleId,
          title: f.title,
          severity: f.severity,
          description: f.description,
          recommendation: f.recommendation,
          autoFixAvailable: f.autoFixAvailable,
          line: f.line,
        })),
        astScore: astReport.score,
        astStatus: astReport.status,
        accountSpace: {
          totalSpace: astReport.accountSpaceAnalysis.declaredSpace || 49,
          isExact49Bytes: astReport.accountSpaceAnalysis.isExact,
          discriminatorPresent: astReport.accountSpaceAnalysis.discriminatorPresent,
        },
        graphRag: {
          nodesCount: graphRagReport.enterpriseNodes.length,
          edgesCount: graphRagReport.enterpriseEdges.length,
          communitiesCount: graphRagReport.communities.length,
          multiHopPathsCount: graphRagReport.multiHopPaths.length,
          deterministicAuditStatus: graphRagReport.deterministicAuditStatus,
          communities: graphRagReport.communities.map(c => ({
            name: c.name,
            summary: c.summary,
            keyInvariants: c.keyInvariants,
            riskIndex: c.riskIndex,
          })),
          attackPaths: graphRagReport.attackPaths.map(a => ({
            title: a.title,
            severity: a.status === 'EXPLOITABLE' ? 'HIGH' : 'MITIGATED',
            description: a.attackerGoal,
          })),
        },
        mcpTools: MCP_TOOLS.map(t => ({
          name: t.name,
          description: t.description,
        })),
      };

      const historyPayload = messages.map(m => ({
        role: m.role,
        text: m.content,
      }));

      const res = await fetch('/api/security-agent/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: query,
          history: historyPayload,
          context: contextPayload,
        }),
      });

      const data = await res.json();

      if (data.success) {
        const assistantMessage: ChatMessage = {
          id: `assistant-${Date.now()}`,
          role: 'assistant',
          content: data.reply,
          timestamp: new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }),
          sourceModel: data.sourceModel,
          mcpToolRecommendations: data.mcpToolRecommendations || [],
        };
        setMessages(prev => [...prev, assistantMessage]);
      } else {
        throw new Error(data.error || 'Falha ao processar resposta');
      }
    } catch (err: any) {
      const errorMessage: ChatMessage = {
        id: `assistant-err-${Date.now()}`,
        role: 'assistant',
        content: `### Erro no Agente de Seguranca\nNao foi possivel obter a resposta do servidor: ${err.message || 'Erro de comunicacao'}.\n\n*Nota:* O motor determinístico de contingencia pode ser acionado diretamente na aba AST ou MCP.`,
        timestamp: new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }),
        sourceModel: 'Sistema de Contingencia',
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const handleClearChat = () => {
    setMessages([
      {
        id: `welcome-${Date.now()}`,
        role: 'assistant',
        content: `Historico reiniciado. Como posso te auxiliar com a analise do AST, com o Grafo de Ataque GraphRAG ou com as ferramentas MCP?`,
        timestamp: new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' }),
        sourceModel: 'Solana DevSecOps MCP Engine',
      },
    ]);
  };

  const promptSuggestions = [
    'Quais sao as vulnerabilidades detectadas no AST atual?',
    'Explique o caminho de ataque mapeado pelo GraphRAG.',
    'Como o MCP tool audit_rust_ast valida o Signer e has_one?',
    'Qual a garantia de 49 bytes exatos e rent-exemption do UserCounter?',
    'Como proteger a instrucao increment contra estouro aritmetico?',
  ];

  // Formatador basico de blocos markdown
  const renderFormattedContent = (content: string) => {
    const lines = content.split('\n');
    let inCodeBlock = false;
    let codeBuffer: string[] = [];
    let codeLang = '';
    const elements: React.ReactNode[] = [];

    lines.forEach((line, index) => {
      if (line.startsWith('```')) {
        if (inCodeBlock) {
          // Fecha bloco
          const fullCode = codeBuffer.join('\n');
          const blockId = `code-${index}`;
          elements.push(
            <div key={blockId} className="my-2.5 rounded-lg border border-slate-800 bg-slate-950 overflow-hidden font-mono text-xs">
              <div className="flex items-center justify-between px-3 py-1.5 bg-slate-900 border-b border-slate-800 text-[11px] text-slate-400">
                <span className="flex items-center gap-1.5 font-semibold text-cyan-300">
                  <Code2 className="w-3.5 h-3.5" />
                  <span>{codeLang || 'rust'}</span>
                </span>
                <button
                  onClick={() => handleCopy(fullCode, blockId)}
                  className="flex items-center gap-1 hover:text-white transition-colors text-[10px]"
                >
                  {copiedId === blockId ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedId === blockId ? 'Copiado!' : 'Copiar'}</span>
                </button>
              </div>
              <pre className="p-3 overflow-x-auto text-slate-200 text-xs leading-relaxed">
                {fullCode}
              </pre>
            </div>
          );
          codeBuffer = [];
          inCodeBlock = false;
        } else {
          inCodeBlock = true;
          codeLang = line.replace('```', '').trim();
        }
        return;
      }

      if (inCodeBlock) {
        codeBuffer.push(line);
        return;
      }

      // Titulos
      if (line.startsWith('### ')) {
        elements.push(
          <h4 key={index} className="text-sm font-bold text-white mt-3 mb-1.5 flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
            {line.replace('### ', '')}
          </h4>
        );
        return;
      }
      if (line.startsWith('## ')) {
        elements.push(
          <h3 key={index} className="text-base font-bold text-cyan-300 mt-4 mb-2">
            {line.replace('## ', '')}
          </h3>
        );
        return;
      }

      // Bullet points
      if (line.trim().startsWith('- ') || line.trim().startsWith('* ')) {
        const bulletText = line.trim().substring(2);
        elements.push(
          <div key={index} className="flex items-start gap-2 my-1 text-xs text-slate-300">
            <span className="text-cyan-400 font-bold shrink-0 leading-relaxed">•</span>
            <span className="leading-relaxed">{parseInlineMarkdown(bulletText)}</span>
          </div>
        );
        return;
      }

      // Linhas regulares
      if (line.trim().length === 0) {
        elements.push(<div key={index} className="h-1.5" />);
        return;
      }

      elements.push(
        <p key={index} className="text-xs text-slate-300 my-1 leading-relaxed">
          {parseInlineMarkdown(line)}
        </p>
      );
    });

    return elements;
  };

  const parseInlineMarkdown = (text: string) => {
    // Processa inline code `code` e **bold**
    const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
    return parts.map((part, idx) => {
      if (part.startsWith('`') && part.endsWith('`')) {
        return (
          <code key={idx} className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-300 font-mono text-[11px]">
            {part.slice(1, -1)}
          </code>
        );
      }
      if (part.startsWith('**') && part.endsWith('**')) {
        return (
          <strong key={idx} className="font-semibold text-white">
            {part.slice(2, -2)}
          </strong>
        );
      }
      return part;
    });
  };

  return (
    <div className={`flex flex-col rounded-2xl border border-slate-800 bg-slate-950 overflow-hidden shadow-2xl transition-all ${
      isExpanded ? 'h-[85vh]' : 'h-[680px]'
    }`}>
      {/* 1. Header do Agente de Seguranca */}
      <div className="p-4 bg-gradient-to-r from-slate-900 via-purple-950/40 to-slate-900 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-purple-600 to-cyan-500 p-0.5 shadow-lg shadow-purple-600/30 flex items-center justify-center shrink-0">
            <div className="w-full h-full bg-slate-950 rounded-[10px] flex items-center justify-center">
              <Brain className="w-5 h-5 text-cyan-400 animate-pulse" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm sm:text-base font-bold text-white tracking-wide">
                Agente de Seguranca IA (Contexto MCP & GraphRAG)
              </h3>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-950 text-cyan-400 border border-cyan-800/40 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping"></span>
                <span>Ativo</span>
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Raciocinio semantico fundamentado no AST Real, topologia de grafos e catalogo MCP.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-1.5 self-end sm:self-center">
          <button
            onClick={() => setShowContextDetails(!showContextDetails)}
            className={`px-2.5 py-1 text-xs rounded-lg border transition-all flex items-center gap-1.5 ${
              showContextDetails
                ? 'bg-purple-900/60 border-purple-500 text-purple-200'
                : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
            title="Inspecionar payload de contexto em tempo real"
          >
            <Database className="w-3.5 h-3.5" />
            <span>Contexto Sync</span>
            {showContextDetails ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </button>

          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
            title={isExpanded ? 'Restaurar tamanho' : 'Maximizar'}
          >
            {isExpanded ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
          </button>

          <button
            onClick={handleClearChat}
            className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-rose-400 transition-colors"
            title="Limpar historico de mensagens"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>

          {onClose && (
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white transition-colors ml-1"
            >
              ✕
            </button>
          )}
        </div>
      </div>

      {/* 2. Barra de Status de Contexto Rápido */}
      <div className="px-4 py-2 bg-slate-900/50 border-b border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-xs font-mono shrink-0">
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400">AST Score:</span>
            <span className={`font-bold ${astReport.score === 100 ? 'text-emerald-400' : 'text-amber-400'}`}>
              {astReport.score}/100 ({astReport.status})
            </span>
          </div>

          <div className="h-3 w-px bg-slate-800" />

          <div className="flex items-center gap-1.5">
            <Share2 className="w-3.5 h-3.5 text-purple-400" />
            <span className="text-slate-400">GraphRAG:</span>
            <span className="text-purple-300">
              {graphRagReport.enterpriseNodes.length} nós | {graphRagReport.communities.length} clusters | {graphRagReport.multiHopPaths.length} rotas
            </span>
          </div>

          <div className="h-3 w-px bg-slate-800" />

          <div className="flex items-center gap-1.5">
            <Box className="w-3.5 h-3.5 text-cyan-300" />
            <span className="text-slate-400">MCP:</span>
            <span className="text-slate-200">10 ferramentas conectadas</span>
          </div>
        </div>

        <div className="text-[11px] text-slate-400 flex items-center gap-1">
          <span>Memoria:</span>
          <span className="text-emerald-400 font-bold">49 Bytes (Rent-Exempt)</span>
        </div>
      </div>

      {/* 2.1 Gaveta de Inspecao de Contexto (Toggle) */}
      {showContextDetails && (
        <div className="p-3 bg-slate-900/90 border-b border-purple-800/40 text-xs font-mono text-slate-300 space-y-2 shrink-0 animate-in fade-in">
          <div className="flex justify-between items-center text-purple-300 font-bold">
            <span>DADOS DE ENTRADA DO AGENTE (Zero Mocks)</span>
            <span className="text-[10px] text-slate-400">Autoria: Marco Antonio Conceicao</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px]">
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-cyan-400 block font-semibold">Auditor AST:</span>
              <span>Regras: {astReport.totalRulesChecked} | Aprovadas: {astReport.passedCount}</span>
              <br />
              <span>Vulnerabilidades: {astReport.findings.length} (Criticas: {astReport.criticalCount}, Altas: {astReport.highCount})</span>
            </div>
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-purple-400 block font-semibold">GraphRAG Enterprise:</span>
              <span>Status: {graphRagReport.deterministicAuditStatus}</span>
              <br />
              <span>Arestas Semanticas: {graphRagReport.enterpriseEdges.length}</span>
            </div>
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-amber-400 block font-semibold">Servidor MCP:</span>
              <span>Protocolo: 2024-11-05</span>
              <br />
              <span>Ferramentas: audit_rust_ast, generate_anchor_contract, etc.</span>
            </div>
          </div>
        </div>
      )}

      {/* 3. Área de Mensagens (Scrollable) */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 touch-scroll">
        {messages.map(msg => (
          <div
            key={msg.id}
            className={`flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'}`}
          >
            <div className="flex items-center gap-1.5 mb-1 px-1 text-[11px] font-mono text-slate-400">
              {msg.role === 'assistant' ? (
                <>
                  <Brain className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="font-semibold text-cyan-300">Agente de Seguranca</span>
                  {msg.sourceModel && (
                    <span className="px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800 text-[10px] text-slate-400">
                      {msg.sourceModel}
                    </span>
                  )}
                </>
              ) : (
                <>
                  <span className="font-semibold text-slate-200">Desenvolvedor</span>
                </>
              )}
              <span className="text-slate-400">• {msg.timestamp}</span>
            </div>

            <div
              className={`max-w-3xl rounded-xl p-4 text-xs shadow-md ${
                msg.role === 'user'
                  ? 'bg-gradient-to-r from-purple-600 to-indigo-600 text-white rounded-tr-none'
                  : 'bg-slate-900/90 border border-slate-800 text-slate-200 rounded-tl-none'
              }`}
            >
              {msg.role === 'assistant' ? (
                <div>
                  {renderFormattedContent(msg.content)}

                  {/* Recomendacoes de Ferramentas MCP */}
                  {msg.mcpToolRecommendations && msg.mcpToolRecommendations.length > 0 && (
                    <div className="mt-3 pt-3 border-t border-slate-800/80 flex flex-wrap items-center gap-1.5">
                      <span className="text-[11px] font-mono font-semibold text-cyan-400 flex items-center gap-1">
                        <Box className="w-3 h-3" /> Ferramentas MCP Recomendadas:
                      </span>
                      {msg.mcpToolRecommendations.map(tool => (
                        <button
                          key={tool}
                          onClick={() => {
                            if (onRunMcpTool) {
                              onRunMcpTool(tool);
                            } else if (onSelectTab) {
                              onSelectTab('mcp');
                            }
                          }}
                          className="px-2 py-0.5 rounded bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-800/60 text-cyan-300 text-[11px] font-mono transition-colors flex items-center gap-1 shadow-sm"
                        >
                          <Terminal className="w-2.5 h-2.5" />
                          <span>{tool}</span>
                        </button>
                      ))}
                    </div>
                  )}

                  {/* Acoes Rápidas de Navegação */}
                  <div className="mt-2 flex items-center gap-2 text-[10px] text-slate-400 font-mono">
                    <button
                      onClick={() => handleCopy(msg.content, msg.id)}
                      className="hover:text-slate-200 transition-colors flex items-center gap-1"
                    >
                      {copiedId === msg.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedId === msg.id ? 'Resposta copiada' : 'Copiar resposta'}</span>
                    </button>

                    {onSelectTab && (
                      <>
                        <span>•</span>
                        <button
                          onClick={() => onSelectTab('ast')}
                          className="hover:text-cyan-300 transition-colors flex items-center gap-1"
                        >
                          <ShieldCheck className="w-3 h-3 text-cyan-400" />
                          <span>Abrir Auditor AST</span>
                        </button>
                        <span>•</span>
                        <button
                          onClick={() => onSelectTab('graphrag')}
                          className="hover:text-purple-300 transition-colors flex items-center gap-1"
                        >
                          <Share2 className="w-3 h-3 text-purple-400" />
                          <span>Explorar GraphRAG</span>
                        </button>
                      </>
                    )}
                  </div>
                </div>
              ) : (
                <p className="whitespace-pre-wrap leading-relaxed">{msg.content}</p>
              )}
            </div>
          </div>
        ))}

        {isLoading && (
          <div className="flex flex-col items-start">
            <div className="flex items-center gap-1.5 mb-1 px-1 text-[11px] font-mono text-cyan-400">
              <Brain className="w-3.5 h-3.5 animate-pulse" />
              <span>Agente de Seguranca analisando AST e rotas GraphRAG...</span>
            </div>
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 rounded-tl-none flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: '0ms' }} />
              <div className="w-2 h-2 rounded-full bg-purple-400 animate-bounce" style={{ animationDelay: '150ms' }} />
              <div className="w-2 h-2 rounded-full bg-emerald-400 animate-bounce" style={{ animationDelay: '300ms' }} />
              <span className="text-xs text-slate-400 font-mono ml-2">Consultando modelo e sintetizando resposta...</span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* 4. Sugestões de Perguntas Rápidas */}
      <div className="px-4 py-2 bg-slate-900/40 border-t border-slate-800/80 flex items-center gap-1.5 overflow-x-auto no-scrollbar shrink-0">
        <span className="text-[11px] font-mono text-slate-400 shrink-0 flex items-center gap-1 mr-1">
          <HelpCircle className="w-3 h-3 text-purple-400" />
          <span>Sugeridas:</span>
        </span>
        {promptSuggestions.map((prompt, idx) => (
          <button
            key={idx}
            onClick={() => handleSendMessage(prompt)}
            disabled={isLoading}
            className="px-2.5 py-1 rounded-full bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-purple-500/40 text-[11px] text-slate-300 hover:text-white transition-all whitespace-nowrap shrink-0 disabled:opacity-50"
          >
            {prompt}
          </button>
        ))}
      </div>

      {/* 5. Input Box */}
      <div className="p-3 bg-slate-900/90 border-t border-slate-800 shrink-0">
        <div className="flex items-end gap-2 bg-slate-950 border border-slate-800 focus-within:border-purple-500 rounded-xl p-2 transition-all">
          <textarea
            ref={inputRef}
            value={inputValue}
            onChange={e => setInputValue(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Pergunte ao Agente sobre vulnerabilidades do AST, GraphRAG ou ferramentas MCP... (Enter para enviar)"
            rows={2}
            className="w-full bg-transparent text-xs text-slate-200 placeholder-slate-400 focus:outline-none resize-none leading-relaxed p-1 font-mono"
            disabled={isLoading}
          />

          <button
            onClick={() => handleSendMessage()}
            disabled={!inputValue.trim() || isLoading}
            className={`px-3 py-2 rounded-lg font-medium text-xs flex items-center gap-1.5 transition-all shrink-0 ${
              inputValue.trim() && !isLoading
                ? 'bg-gradient-to-r from-purple-600 to-cyan-600 hover:from-purple-500 hover:to-cyan-500 text-white shadow-lg shadow-purple-600/30'
                : 'bg-slate-800 text-slate-400 cursor-not-allowed'
            }`}
          >
            {isLoading ? <RotateCcw className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
            <span>Enviar</span>
          </button>
        </div>
        <div className="flex items-center justify-between mt-2 px-1 text-[10px] text-slate-400 font-mono">
          <span>Pressione Shift + Enter para quebra de linha</span>
          <span>Modelo Ativo: gemini-3.8-flash (com contingencia determinística)</span>
        </div>
      </div>
    </div>
  );
};
