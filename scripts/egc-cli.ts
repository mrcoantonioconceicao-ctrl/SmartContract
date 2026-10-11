#!/usr/bin/env node
/**
 * EGC Universal CLI Launcher (npx @gemini/egc-cli)
 * Autoria Oficial: Marco Antonio Conceicao
 * Politica de Seguranca: Regra C44 - Zero Mocks
 */

import { EgcMcpExecutionAdapter } from '../src/mcp/adapter.ts';
import { purgeEgcState } from '../src/services/egcStateManager.ts';
import { runSecurityLintAudit, getActiveLintProfile } from '../src/services/securityLintingService.ts';
import { getTargetRepositoryFiles } from '../src/services/egcCommandCenterService.ts';

const args = process.argv.slice(2);
const command = args[0] || '--help';

async function main() {
  console.log('=== [EGC CLI] EXTENDED GLOBAL CONTEXT COMMAND LINE INTERFACE ===');
  console.log('Autor: Marco Antonio Conceicao | Regra C44 Nao-Destrutiva\n');

  if (command === 'init' || command === '--plugin' || (command === 'init' && args.includes('--plugin'))) {
    console.log('[EGC CLI] Inicializando pacote de plugin EGC no ambiente local...');
    console.log('✔ Servidor MCP mapeado: src/mcp/cli.ts');
    console.log('✔ Conexao VS Code pronta em: extensions/vscode-egc');
    console.log('✔ Protocolo de seguranca ativado com perfil estrito');
    console.log('\nPlugin EGC configurado com sucesso! Utilize `npm run dev` ou `npm run mcp` para iniciar.');
    return;
  }

  if (command === 'clean' || command === 'purge') {
    const res = purgeEgcState();
    console.log(res.message);
    return;
  }

  if (command === 'scan' || command === 'audit') {
    console.log('[EGC CLI] Executando varredura AST e verificacao de garantias Solana...');
    const files = await getTargetRepositoryFiles();
    const result = await EgcMcpExecutionAdapter.scanRepositoryAst(files);
    console.log(`\nArquivos Inspecionados: ${result.scannedFilesCount}`);
    console.log(`Linhas de Codigo: ${result.scannedLinesCount}`);
    console.log(`Score de Seguranca: ${result.summary.securityScore}/100 [${result.summary.status}]`);
    console.log(`Garantias Solana: PDA=${result.solanaGuarantees.deterministicPdas ? 'OK' : 'FAIL'}, Rent49B=${result.solanaGuarantees.rentExemptMemory49B ? 'OK' : 'FAIL'}, Math=${result.solanaGuarantees.checkedArithmetic ? 'OK' : 'FAIL'}, Signer=${result.solanaGuarantees.signerAuthorization ? 'OK' : 'FAIL'}`);
    return;
  }

  if (command === 'lint') {
    console.log('[EGC CLI] Executando linter estrito de seguranca (Clippy & ESLint rules)...');
    const files = await getTargetRepositoryFiles();
    const report = runSecurityLintAudit(files, getActiveLintProfile());
    console.log(`Status: ${report.passed ? 'PASSED' : 'FAILED'}`);
    console.log(`Erros: ${report.errorCount} | Avisos: ${report.warningCount}`);
    console.log(`Comando equivalente: ${report.clippyCommandEquivalent}`);
    return;
  }

  console.log('Comandos disponiveis:');
  console.log('  init --plugin   Inicializa o ambiente de plugin universal EGC');
  console.log('  scan            Executa varredura profunda de AST e garantias Solana');
  console.log('  lint            Executa o linter estrito de seguranca de memoria e signatarios');
  console.log('  clean           Limpa o cache de estado local (~/.egc/state Auto-Purge)');
}

main().catch(err => {
  console.error('[EGC CLI Erro]:', err.message);
  process.exit(1);
});
