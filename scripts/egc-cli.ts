#!/usr/bin/env node
/**
 * EGC CLI transport for the versioned command contract.
 */

import {
  EGC_V1_COMMANDS,
  EgcV1CommandName,
  EgcV1Response,
} from '../src/contracts/v1/index.ts';
import { executeEgcContractCommand } from '../src/application/egcCommandService.ts';
import { readFileSync } from 'node:fs';

const args = process.argv.slice(2);
const command = args[0] || '--help';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

async function executeContractCommand(
  name: EgcV1CommandName,
  input: unknown = {},
): Promise<EgcV1Response | undefined> {
  const response = await executeEgcContractCommand(name, input);
  if (!response.success) {
    console.error(JSON.stringify(response, null, 2));
    process.exitCode = 1;
    return undefined;
  }
  return response;
}

async function main() {
  if (command === 'init' || command === '--plugin') {
    console.log('[EGC CLI] Inicializando pacote de plugin EGC no ambiente local...');
    console.log('Servidor MCP: src/mcp/cli.ts');
    console.log('Comandos oficiais: use `egc-cli <command> --input-stdin` ou `--input-file <path>`.');
    console.log('Esta opção é informativa; não altera configurações do editor.');
    return;
  }

  if (command === 'scan' || command === 'audit') {
    const response = await executeContractCommand('scan_repository_ast');
    if (!response?.success) return;
    const result = EGC_V1_COMMANDS.scan_repository_ast.outputSchema.parse(response.result);
    if (!isRecord(result)) return;
    const summary: Record<string, unknown> = isRecord(result.summary) ? result.summary : {};
    const guarantees: Record<string, unknown> = isRecord(result.solanaGuarantees)
      ? result.solanaGuarantees
      : {};
    console.log(`Arquivos Inspecionados: ${result.scannedFilesCount}`);
    console.log(`Linhas de Código: ${result.scannedLinesCount}`);
    console.log(`Score de Segurança: ${summary.securityScore}/100 [${summary.status}]`);
    console.log(
      `Garantias Solana: PDA=${guarantees.deterministicPdas ? 'OK' : 'FAIL'}, ` +
      `Rent49B=${guarantees.rentExemptMemory49B ? 'OK' : 'FAIL'}, ` +
      `Math=${guarantees.checkedArithmetic ? 'OK' : 'FAIL'}, ` +
      `Signer=${guarantees.signerAuthorization ? 'OK' : 'FAIL'}`,
    );
    console.log(`Correlation ID: ${response.correlationId} | Timestamp: ${response.timestamp}`);
    return;
  }

  if (command === 'lint') {
    const response = await executeContractCommand('run_security_lint');
    if (!response?.success) return;
    const result = EGC_V1_COMMANDS.run_security_lint.outputSchema.parse(response.result);
    if (!isRecord(result)) return;
    console.log(`Status: ${result.passed ? 'PASSED' : 'FAILED'}`);
    console.log(`Erros: ${result.errorCount} | Avisos: ${result.warningCount}`);
    console.log(`Comando equivalente: ${result.clippyCommandEquivalent}`);
    console.log(`Correlation ID: ${response.correlationId} | Timestamp: ${response.timestamp}`);
    if (!result.passed) process.exitCode = 1;
    return;
  }

  if (command === 'clean' || command === 'purge') {
    const response = await executeContractCommand('egc_clean_state');
    if (!response?.success) return;
    const result = EGC_V1_COMMANDS.egc_clean_state.outputSchema.parse(response.result);
    if (result && isRecord(result)) console.log(result.message);
    console.log(`Correlation ID: ${response.correlationId} | Timestamp: ${response.timestamp}`);
    return;
  }

  if (Object.prototype.hasOwnProperty.call(EGC_V1_COMMANDS, command)) {
    let input: unknown = {};
    if (args[1] === '--input-stdin' && args.length === 2) {
      try {
        input = JSON.parse(readFileSync(0, 'utf8'));
      } catch {
        console.error('Invalid JSON supplied through stdin.');
        process.exitCode = 2;
        return;
      }
    } else if (args[1] === '--input-file' && args.length === 3 && args[2]) {
      try {
        input = JSON.parse(readFileSync(args[2], 'utf8'));
      } catch {
        console.error('Could not read or parse the command input file.');
        process.exitCode = 2;
        return;
      }
    } else if (args.length > 1) {
      console.error('Use --input-stdin or --input-file <path> for command input.');
      process.exitCode = 2;
      return;
    }

    const response = await executeEgcContractCommand(command, input);
    console.log(JSON.stringify(response, null, 2));
    if (!response.success) process.exitCode = 1;
    return;
  }

  console.log('Comandos disponíveis:');
  console.log('  init --plugin       Exibe as informações locais do plugin');
  console.log('  scan | audit        Executa varredura AST do repositório');
  console.log('  lint                Executa o perfil ativo de segurança Clippy/Web3');
  console.log('  clean | purge       Limpa o estado local EGC');
  console.log('  <command> --input-stdin         Lê JSON do stdin (preferível para tokens)');
  console.log('  <command> --input-file <path>   Lê JSON de um arquivo local protegido');
  console.log('Comandos v1:', Object.keys(EGC_V1_COMMANDS).join(', '));
}

main().catch(error => {
  console.error('[EGC CLI Erro]:', error instanceof Error ? error.message : 'Falha inesperada');
  process.exitCode = 1;
});
