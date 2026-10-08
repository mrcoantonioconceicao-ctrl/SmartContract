/**
 * Solana Anchor DevSecOps - Auditable PDF Report Generator
 * Modulo: src/services/pdfReportService.ts
 * Autoria: Marco Antonio Conceicao
 *
 * Compila relatorio PDF auditavel e formal com os resultados da varredura real,
 * analise de AST, PDAs, rent-exempt, signatarios e integracao GitHub.
 */

import { jsPDF } from 'jspdf';
import { RealRepoScanResult } from './realRepoScanner.ts';
import { CreatedGitHubIssue } from './githubIssueService.ts';
import { GitHubPrResult } from './githubPrService.ts';

export interface GeneratePdfOptions {
  scanResult: RealRepoScanResult;
  issues?: CreatedGitHubIssue[];
  pullRequest?: GitHubPrResult | null;
  targetRepo?: string;
  targetBranch?: string;
}

/**
 * Gera e baixa o documento PDF auditavel no navegador do usuario.
 */
export function generateAuditablePdfReport(options: GeneratePdfOptions): {
  blob: Blob;
  blobUrl: string;
  filename: string;
} {
  const { scanResult, issues = [], pullRequest = null, targetRepo = 'SlipPay2', targetBranch = 'corrigido/remediacao-c44' } = options;

  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  let y = 18;

  // Header Background Banner
  doc.setFillColor(15, 23, 42); // slate-900
  doc.rect(0, 0, pageWidth, 32, 'F');

  // Title
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(248, 250, 252);
  doc.text('SOLANA ANCHOR DEVSECOPS - RELATORIO DE AUDITORIA', 14, 14);

  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(148, 163, 184);
  doc.text('Centro de Comando EGC & Motor de Varredura Real de Smart Contracts e AST', 14, 21);

  doc.setFontSize(8);
  doc.setTextColor(56, 189, 248);
  doc.text(`Auditor Responsavel: Marco Antonio Conceicao | Data: ${new Date().toLocaleString('pt-PT')}`, 14, 28);

  y = 40;

  // Metadata Card
  doc.setDrawColor(226, 232, 240);
  doc.setFillColor(248, 250, 252);
  doc.roundedRect(14, y, pageWidth - 28, 26, 2, 2, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(15, 23, 42);
  doc.text('METADADOS DO PROJETO E ALVO DE AUDITORIA', 18, y + 6);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(71, 85, 105);
  doc.text(`Repositorio Alvo: ${targetRepo}`, 18, y + 12);
  doc.text(`Ramo Alvo: ${targetBranch}`, 18, y + 17);
  doc.text(`Arquivos Inspecionados: ${scanResult.scannedFilesCount} arquivos (${scanResult.scannedLinesCount} linhas de codigo)`, 18, y + 22);

  const scoreText = `Score de Seguranca: ${scanResult.summary.securityScore}/100 [${scanResult.summary.status}]`;
  doc.setFont('helvetica', 'bold');
  if (scanResult.summary.securityScore >= 85) {
    doc.setTextColor(16, 185, 129); // green
  } else if (scanResult.summary.securityScore >= 60) {
    doc.setTextColor(245, 158, 11); // amber
  } else {
    doc.setTextColor(239, 68, 68); // red
  }
  doc.text(scoreText, pageWidth - 85, y + 12);

  y += 32;

  // Seccao: Garantias On-Chain Solana
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(15, 23, 42);
  doc.text('1. GARANTIAS ON-CHAIN SOLANA AUDITADAS (REGRA ZERO MOCKS)', 14, y);
  y += 6;

  const guarantees = [
    {
      title: 'PDAs Deterministicos e Verificacao Rigorosa de Seeds',
      status: scanResult.solanaGuarantees.deterministicPdas ? 'CONFORME [PASS]' : 'ALERTA',
      desc: 'Sementes canonicas [b"counter", authority.key().as_ref()] e canonical bump persistido.',
    },
    {
      title: 'Alocacao Estrita de Memoria Rent-Exempt (Exatamente 49 Bytes)',
      status: scanResult.solanaGuarantees.rentExemptMemory49B ? 'CONFORME [PASS]' : 'ALERTA',
      desc: 'Tamanho milimetrico: 8 disc + 32 auth + 8 count + 1 bump = 49B.',
    },
    {
      title: 'Tratamento Obrigatorio de Overflow/Underflow (checked_*)',
      status: scanResult.solanaGuarantees.checkedArithmetic ? 'CONFORME [PASS]' : 'ALERTA',
      desc: 'Protecao integral via .checked_add() e .checked_sub() com erro customizado.',
    },
    {
      title: 'Validacao Rigorosa de Signatarios (Signer<\'info> e has_one)',
      status: scanResult.solanaGuarantees.signerAuthorization ? 'CONFORME [PASS]' : 'ALERTA',
      desc: 'Assinaturas criptograficas Ed25519 e restricao has_one = authority.',
    },
  ];

  guarantees.forEach((g) => {
    doc.setFillColor(241, 245, 249);
    doc.roundedRect(14, y, pageWidth - 28, 12, 1, 1, 'FD');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    doc.setTextColor(30, 41, 59);
    doc.text(g.title, 18, y + 5);

    doc.setFont('helvetica', 'bold');
    if (g.status.includes('CONFORME')) {
      doc.setTextColor(16, 185, 129);
    } else {
      doc.setTextColor(239, 68, 68);
    }
    doc.text(g.status, pageWidth - 50, y + 5);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(100, 116, 139);
    doc.text(g.desc, 18, y + 9);

    y += 14;
  });

  y += 2;

  // Seccao: Integracao GitHub e Automacao
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(15, 23, 42);
  doc.text('2. AUTOMACAO GITHUB (ISSUES E PULL REQUEST SEM AUTO-MERGE)', 14, y);
  y += 6;

  doc.setFillColor(248, 250, 252);
  doc.roundedRect(14, y, pageWidth - 28, 20, 1, 1, 'FD');

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(51, 65, 85);

  const issuesCreatedCount = issues.length;
  doc.text(`Issues Reais Criadas no GitHub: ${issuesCreatedCount}`, 18, y + 5);
  if (pullRequest) {
    doc.text(`Pull Request Aberto: #${pullRequest.prNumber} (${pullRequest.prUrl})`, 18, y + 10);
    doc.text('Status do PR: OPEN (Politica Estrita de Merge Manual - Auto-Merge Desativado)', 18, y + 15);
  } else {
    doc.text('Pull Request: Pronto para despacho apos confirmacao do PAT', 18, y + 10);
    doc.text('Status: Aguardando envio com garantia pre-flight de branch valida', 18, y + 15);
  }

  y += 26;

  // Seccao: Achados Detalhados da Varredura Real
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(15, 23, 42);
  doc.text('3. ACHADOS E EVIDENCIAS DA AST DO REPOSITORIO', 14, y);
  y += 6;

  const findingsToShow = scanResult.findings.slice(0, 7);

  findingsToShow.forEach((f) => {
    if (y > 270) {
      doc.addPage();
      y = 16;
    }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);

    if (f.severity === 'CRITICAL' || f.severity === 'HIGH') {
      doc.setTextColor(220, 38, 38);
    } else if (f.severity === 'MEDIUM' || f.severity === 'LOW') {
      doc.setTextColor(217, 119, 6);
    } else {
      doc.setTextColor(16, 185, 129);
    }

    doc.text(`[${f.severity}] ${f.title}`, 14, y);
    y += 4;

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(71, 85, 105);
    doc.text(`Arquivo: ${f.file} (linha ${f.line}) | Regra: ${f.ruleId}`, 14, y);
    y += 3.5;

    doc.text(`Descricao: ${f.description.slice(0, 110)}...`, 14, y);
    y += 3.5;

    doc.text(`Recomendacao: ${f.recommendation.slice(0, 110)}`, 14, y);
    y += 5.5;
  });

  // Footer on page 1
  doc.setFont('helvetica', 'italic');
  doc.setFontSize(7);
  doc.setTextColor(148, 163, 184);
  doc.text('Relatorio emitido em conformidade com as regras C44 e politicas DevSecOps de Solana Anchor.', 14, 288);
  doc.text('Autoria: Marco Antonio Conceicao', pageWidth - 60, 288);

  const pdfOutput = doc.output('blob');
  const blobUrl = URL.createObjectURL(pdfOutput);
  const filename = `solana-anchor-audit-report-${Date.now()}.pdf`;

  // Trigger download in browser
  const link = document.createElement('a');
  link.href = blobUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);

  return {
    blob: pdfOutput,
    blobUrl,
    filename,
  };
}
