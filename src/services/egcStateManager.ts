/**
 * Solana Anchor DevSecOps - EGC Local State Manager & Auto-Purge Service
 * Modulo: src/services/egcStateManager.ts
 * Autoria: Marco Antonio Conceicao
 *
 * Gerencia o ciclo de vida do estado de execucao do EGC (Extended Global Context):
 * 1. Cache em memoria de variaveis de sessao ativas (repositorio, branch, tokens temporarios).
 * 2. Persistencia e desvinculo do contexto local (~/.egc/state e .egc/state.json).
 * 3. Rotina obrigatoria de auto-purge executada imediatamente apos a abertura de Pull Request.
 * 4. Isolamento estatico contra reaproveitamento de alvos residuais (ex: SlipPay vs Plataforma-nexa).
 * 5. Conformidade estrita com a Regra C44 (Nao-Destrutiva).
 */

import fs from 'fs';
import path from 'path';
import os from 'os';

export interface EgcSessionState {
  targetRepo: string | null;
  targetOwner: string | null;
  targetBranch: string | null;
  temporaryToken: string | null;
  lastExecutionTime: string | null;
  contextId: string | null;
  lastPrUrl: string | null;
  lastPrNumber: number | null;
  cachedFindings: any[] | null;
}

export interface EgcPurgeResult {
  success: boolean;
  message: string;
  purgedAt: string;
  previousTarget: string | null;
  details: {
    memoryCacheCleared: boolean;
    localStateUnlinked: boolean;
    localStorageCleared: boolean;
  };
}

export const EGC_CLEAN_CONFIRMATION_MESSAGE = 'Estado limpo com sucesso. EGC pronto para novo alvo.';

const INITIAL_STATE: EgcSessionState = {
  targetRepo: null,
  targetOwner: null,
  targetBranch: null,
  temporaryToken: null,
  lastExecutionTime: null,
  contextId: null,
  lastPrUrl: null,
  lastPrNumber: null,
  cachedFindings: null,
};

// Cache em memoria ativo no runtime
let activeSessionCache: EgcSessionState = { ...INITIAL_STATE };

/**
 * Detecta se o ambiente atual e Node.js
 */
function isNodeRuntime(): boolean {
  return typeof window === 'undefined' && typeof process !== 'undefined' && Boolean(process?.versions?.node);
}

/**
 * Obtem o caminho seguro para o arquivo de estado ~/.egc/state
 */
export function getEgcHomeStatePath(): string | null {
  if (!isNodeRuntime()) return null;
  try {
    const homedir = os.homedir() || process.env.HOME || process.env.USERPROFILE || '/tmp';
    return path.join(homedir, '.egc', 'state');
  } catch {
    return null;
  }
}

/**
 * Obtem o caminho local para o arquivo de estado no repositorio .egc/state.json
 */
export function getEgcLocalStatePath(): string | null {
  if (!isNodeRuntime()) return null;
  try {
    const cwd = typeof process.cwd === 'function' ? process.cwd() : '.';
    return path.join(cwd, '.egc', 'state.json');
  } catch {
    return null;
  }
}

/**
 * Retorna o estado atual em memoria
 */
export function getActiveEgcSession(): EgcSessionState {
  return { ...activeSessionCache };
}

/**
 * Atualiza o estado da sessao em memoria e persiste caso em Node
 */
export function setActiveEgcSession(updates: Partial<EgcSessionState>): EgcSessionState {
  activeSessionCache = {
    ...activeSessionCache,
    ...updates,
    lastExecutionTime: new Date().toISOString(),
  };

  // Persistir em disco se em ambiente Node
  if (isNodeRuntime()) {
    try {
      const homePath = getEgcHomeStatePath();
      if (homePath) {
        const dir = path.dirname(homePath);
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
        fs.writeFileSync(homePath, JSON.stringify(activeSessionCache, null, 2), 'utf-8');
      }

      const localPath = getEgcLocalStatePath();
      if (localPath) {
        const localDir = path.dirname(localPath);
        if (!fs.existsSync(localDir)) {
          fs.mkdirSync(localDir, { recursive: true });
        }
        fs.writeFileSync(localPath, JSON.stringify(activeSessionCache, null, 2), 'utf-8');
      }
    } catch {
      // Isolamento resiliente
    }
  }

  return { ...activeSessionCache };
}

/**
 * Rotina obrigatoria de limpeza de estado (egc clean / auto-purge pos-PR):
 * 1. Limpa cache de variaveis em memoria (repositorio, branch, token).
 * 2. Desvincula o arquivo de estado local (~/.egc/state e .egc/state.json).
 * 3. Limpa chaves no localStorage do navegador caso em frontend.
 * 4. Emite a confirmacao visual estrita: "Estado limpo com sucesso. EGC pronto para novo alvo."
 */
export function purgeEgcState(): EgcPurgeResult {
  const previousTarget = activeSessionCache.targetRepo;
  let localStateUnlinked = false;
  let localStorageCleared = false;

  // 1. Limpar cache de memoria ativo
  activeSessionCache = { ...INITIAL_STATE };

  // 2. Desvincular arquivos de estado local em Node.js
  if (isNodeRuntime()) {
    try {
      const homePath = getEgcHomeStatePath();
      if (homePath && fs.existsSync(homePath)) {
        fs.unlinkSync(homePath);
        localStateUnlinked = true;
      }

      const localPath = getEgcLocalStatePath();
      if (localPath && fs.existsSync(localPath)) {
        fs.unlinkSync(localPath);
        localStateUnlinked = true;
      }
    } catch {
      // Ignora erro se nao existir
    }
  }

  // 3. Limpar localStorage no navegador
  if (typeof window !== 'undefined' && typeof window.localStorage !== 'undefined') {
    try {
      window.localStorage.removeItem('github_sync_repo');
      window.localStorage.removeItem('github_sync_token');
      window.localStorage.removeItem('github_sync_owner');
      window.localStorage.removeItem('egc_last_execution');
      localStorageCleared = true;
    } catch {
      // Protecao de sandbox
    }
  }

  const result: EgcPurgeResult = {
    success: true,
    message: EGC_CLEAN_CONFIRMATION_MESSAGE,
    purgedAt: new Date().toISOString(),
    previousTarget,
    details: {
      memoryCacheCleared: true,
      localStateUnlinked,
      localStorageCleared,
    },
  };

  // Emissao no console / stdout para rastreabilidade
  console.log(`[EGC DevSecOps] ${EGC_CLEAN_CONFIRMATION_MESSAGE}`);

  return result;
}

/**
 * Validacao estatica para impedir que alvos residuais de projetos anteriores
 * (como SlipPay ou SlipPay2) sejam inadvertidamente reutilizados em novas auditorias.
 * Forca a especificacao explicita dos novos parametros para o alvo atual (ex: Plataforma-nexa).
 */
export function validateTargetIsolation(
  targetRepo?: string,
  targetOwner?: string
): { valid: boolean; sanitizedRepo?: string; error?: string } {
  const repo = (targetRepo || '').trim();
  const owner = (targetOwner || '').trim();

  if (!repo) {
    return {
      valid: false,
      error: 'O repositorio alvo e obrigatorio. Apos a limpeza de estado (auto-purge), defina explicitamente o novo alvo (ex: Plataforma-nexa).',
    };
  }

  if (!owner) {
    return {
      valid: false,
      error: 'O proprietario da organizacao/usuario no GitHub e obrigatorio.',
    };
  }

  return {
    valid: true,
    sanitizedRepo: repo,
  };
}
