#!/usr/bin/env node
/**
 * CLI Runner para o comando 'egc clean' (Auto-Purge de Estado)
 * Modulo: src/mcp/egcClean.ts
 * Autoria: Marco Antonio Conceicao
 *
 * Executa a limpeza completa do estado local do EGC:
 * 1. Limpa cache de variaveis em memoria.
 * 2. Desvincula o arquivo de estado (~/.egc/state).
 * 3. Emite a confirmacao visual no terminal:
 *    "Estado limpo com sucesso. EGC pronto para novo alvo."
 * 4. Previne reaproveitamento residual de projetos anteriores.
 */

import { purgeEgcState } from '../services/egcStateManager.ts';

function main() {
  console.log('================================================================');
  console.log('  🧹 EGC EXTENDED GLOBAL CONTEXT - ROTINA DE LIMPEZA DE ESTADO  ');
  console.log('  Autoria: Marco Antonio Conceicao | Regra C44 Non-Destructive  ');
  console.log('================================================================');

  const result = purgeEgcState();

  console.log(`\n✔ ${result.message}\n`);
  console.log(`Timestamp: ${result.purgedAt}`);
  if (result.previousTarget) {
    console.log(`Alvo anterior desvinculado: ${result.previousTarget}`);
  }
  console.log('----------------------------------------------------------------');
  console.log('Proxima acao: Forneca os parametros do novo projeto alvo (ex: Plataforma-nexa).\n');

  process.exit(0);
}

main();
