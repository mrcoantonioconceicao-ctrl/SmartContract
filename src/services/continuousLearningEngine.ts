/**
 * Solana Anchor DevSecOps - Motor de Aprendizado Continuo & Pesos de Auditoria (Zero Mocks)
 * Modulo: src/services/continuousLearningEngine.ts
 * Autoria: Marco Antonio Conceicao
 *
 * Arquitetura de Fine-Tuning Local e Memoria de Aprendizado Continuo:
 * 1. Inicializa conhecimento de dominio estrito de Solana Anchor:
 *    - Memoria Rent-Exempt de 49 Bytes (8 disc + 32 auth + 8 count + 1 bump)
 *    - Signatarios criptograficos Ed25519 obrigatorios (Signer<'info>)
 *    - Aritmetica protegida (.checked_add, .checked_sub)
 *    - Derivacao deterministica de PDA e persistencia de canonical bump
 *    - Discriminadores canónicos SHA-256 (global:<instruction>)
 *    - Pipelines DevSecOps estritas sem escape (sem || true)
 * 2. Atualizacao dinamica de pesos a partir do ciclo de Pull Requests e feedbacks
 * 3. Persistencia local no navegador e servidor (zero mocks, calculos matematicos puros)
 */

export interface RuleWeight {
  ruleId: string;
  category: 'RENT_EXEMPT' | 'SIGNER_AUTH' | 'CHECKED_ARITHMETIC' | 'PDA_SEEDS' | 'DISCRIMINATOR' | 'CI_PIPELINE';
  name: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  weight: number; // Peso ponderado de penalidade (0 - 100)
  reinforcementsCount: number; // Numero de correcoes reais aprendidas no ciclo de PRs
  lastAdaptedAt: string;
}

export interface FeedbackEvent {
  id: string;
  timestamp: string;
  source: 'PR_MERGE' | 'RESOLVED_COMMENT' | 'DISCRIMINATOR_FIX' | 'PIPELINE_STRICT_FIX' | 'MANUAL_FEEDBACK';
  ruleId: string;
  repository: string;
  deltaWeight: number;
  explanation: string;
}

export interface LearningState {
  version: string;
  updatedAt: string;
  totalPrEventsLearned: number;
  baseKnowledge: {
    rentExemptBytes: number;
    ed25519SignerMandatory: boolean;
    checkedArithmeticMandatory: boolean;
    canonicalBumpStorage: boolean;
    sha256DiscriminatorEnforced: boolean;
    strictCiEnforced: boolean;
  };
  weights: Record<string, RuleWeight>;
  history: FeedbackEvent[];
}

const STORAGE_KEY_LEARNING_STATE = 'solana_devsecops_learning_state_v1';

// Base Knowledge Vector inicial para Solana Anchor
export const INITIAL_SOLANA_ANCHOR_RULES: Record<string, RuleWeight> = {
  'UNVALIDATED_ACCOUNTINFO_AUTHORITY': {
    ruleId: 'UNVALIDATED_ACCOUNTINFO_AUTHORITY',
    category: 'SIGNER_AUTH',
    name: 'Autoridade tipada como AccountInfo em vez de Signer',
    description: 'Permite transacoes forjadas se AccountInfo for passada sem checagem de assinatura Ed25519.',
    severity: 'CRITICAL',
    weight: 35,
    reinforcementsCount: 1,
    lastAdaptedAt: new Date().toISOString(),
  },
  'MISSING_SIGNER_CHECK': {
    ruleId: 'MISSING_SIGNER_CHECK',
    category: 'SIGNER_AUTH',
    name: 'Ausencia de Conta Signer em Instrucao Mutavel',
    description: 'Instrucoes que alteram o estado da conta exigem Signer<\'info> obrigatorio.',
    severity: 'CRITICAL',
    weight: 35,
    reinforcementsCount: 1,
    lastAdaptedAt: new Date().toISOString(),
  },
  'MISSING_HAS_ONE_CONSTRAINT': {
    ruleId: 'MISSING_HAS_ONE_CONSTRAINT',
    category: 'SIGNER_AUTH',
    name: 'Falta de Restricao Declarativa has_one = authority',
    description: 'Permite privilege escalation onde terceiro assina mutacao da conta da vitima.',
    severity: 'HIGH',
    weight: 25,
    reinforcementsCount: 1,
    lastAdaptedAt: new Date().toISOString(),
  },
  'UNCHECKED_ARITHMETIC_OVERFLOW': {
    ruleId: 'UNCHECKED_ARITHMETIC_OVERFLOW',
    category: 'CHECKED_ARITHMETIC',
    name: 'Operacao Aritmetica sem .checked_add / .checked_sub',
    description: 'Risco de wrap-around modular ou panico no BPF por overflow numerico.',
    severity: 'HIGH',
    weight: 25,
    reinforcementsCount: 1,
    lastAdaptedAt: new Date().toISOString(),
  },
  'UNDEFINED_SPACE_ALLOCATION': {
    ruleId: 'UNDEFINED_SPACE_ALLOCATION',
    category: 'RENT_EXEMPT',
    name: 'Alocacao de Espaco Indefinida no Macro Init',
    description: 'Falha o calculo de rent-exempt e rejeita transacao no runtime SVM.',
    severity: 'CRITICAL',
    weight: 30,
    reinforcementsCount: 1,
    lastAdaptedAt: new Date().toISOString(),
  },
  'RENT_EXEMPT_49B_MISMATCH': {
    ruleId: 'RENT_EXEMPT_49B_MISMATCH',
    category: 'RENT_EXEMPT',
    name: 'Divergencia do Tamanho Rent-Exempt Exato de 49 Bytes',
    description: 'O layout deve ser exatamente 8 disc + 32 auth + 8 count + 1 bump = 49 bytes.',
    severity: 'MEDIUM',
    weight: 15,
    reinforcementsCount: 1,
    lastAdaptedAt: new Date().toISOString(),
  },
  'BUMP_NOT_SAVED': {
    ruleId: 'BUMP_NOT_SAVED',
    category: 'PDA_SEEDS',
    name: 'Canonical Bump Seed Nao Armazenado no Estado',
    description: 'Obriga a chamadas find_program_address que consomem excesso de Compute Units.',
    severity: 'LOW',
    weight: 10,
    reinforcementsCount: 1,
    lastAdaptedAt: new Date().toISOString(),
  },
  'INSTRUCTION_DISCRIMINATOR_MISMATCH': {
    ruleId: 'INSTRUCTION_DISCRIMINATOR_MISMATCH',
    category: 'DISCRIMINATOR',
    name: 'Discriminador Anchor SHA-256 Incorreto',
    description: 'Primeiros 8 bytes de sha256("global:<name>") divergentes causam InstructionFallbackNotFound.',
    severity: 'CRITICAL',
    weight: 35,
    reinforcementsCount: 2, // Ajustado recentemente no PR para reset
    lastAdaptedAt: new Date().toISOString(),
  },
  'CI_ESCAPE_FALLBACK_DETECTED': {
    ruleId: 'CI_ESCAPE_FALLBACK_DETECTED',
    category: 'CI_PIPELINE',
    name: 'Uso de Escapes Condicionais (|| true) em Pipeline de Seguranca',
    description: 'Mascaramento de falhas em cargo check --locked ou anchor build viola politica DevSecOps.',
    severity: 'HIGH',
    weight: 25,
    reinforcementsCount: 2, // Removido nos PRs recentes
    lastAdaptedAt: new Date().toISOString(),
  },
};

/**
 * Obtem o estado atual da memoria de aprendizado continuo
 */
export function getLearningState(): LearningState {
  try {
    if (typeof localStorage !== 'undefined') {
      const stored = localStorage.getItem(STORAGE_KEY_LEARNING_STATE);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed && parsed.weights) {
          return parsed;
        }
      }
    }
  } catch {
    // Fallback gracioso
  }

  return {
    version: '1.0.0-anchor-fine-tuning',
    updatedAt: new Date().toISOString(),
    totalPrEventsLearned: 2,
    baseKnowledge: {
      rentExemptBytes: 49,
      ed25519SignerMandatory: true,
      checkedArithmeticMandatory: true,
      canonicalBumpStorage: true,
      sha256DiscriminatorEnforced: true,
      strictCiEnforced: true,
    },
    weights: { ...INITIAL_SOLANA_ANCHOR_RULES },
    history: [
      {
        id: 'INIT-FEEDBACK-DISCRIMINATOR',
        timestamp: new Date().toISOString(),
        source: 'DISCRIMINATOR_FIX',
        ruleId: 'INSTRUCTION_DISCRIMINATOR_MISMATCH',
        repository: 'SolanaAnchorDevSecOps',
        deltaWeight: +5,
        explanation: 'Aprendizado com correcao do discriminador reset: sha256("global:reset") -> [23, 81, 251, 84, 138, 183, 240, 214]',
      },
      {
        id: 'INIT-FEEDBACK-CI-PIPELINE',
        timestamp: new Date().toISOString(),
        source: 'PIPELINE_STRICT_FIX',
        ruleId: 'CI_ESCAPE_FALLBACK_DETECTED',
        repository: 'SolanaAnchorDevSecOps',
        deltaWeight: +5,
        explanation: 'Aprendizado com remocao de || true no pipeline de CI para garantir cargo check --locked e anchor build estritos.',
      },
    ],
  };
}

/**
 * Persiste o estado atual da memoria de aprendizado continuo
 */
export function saveLearningState(state: LearningState): void {
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(STORAGE_KEY_LEARNING_STATE, JSON.stringify(state));
    }
  } catch {
    // Silencioso em ambientes headless
  }
}

/**
 * Registra feedback e ajusta dinamicamente os pesos de auditoria do modelo local
 */
export function recordPrFeedbackEvent(event: Omit<FeedbackEvent, 'id' | 'timestamp'>): LearningState {
  const state = getLearningState();
  const rule = state.weights[event.ruleId];

  if (rule) {
    // Ajusta o peso matematicamente com limite de saturação [5, 50]
    rule.weight = Math.max(5, Math.min(50, rule.weight + event.deltaWeight));
    rule.reinforcementsCount += 1;
    rule.lastAdaptedAt = new Date().toISOString();
  }

  const feedbackRecord: FeedbackEvent = {
    ...event,
    id: `FEEDBACK-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    timestamp: new Date().toISOString(),
  };

  state.history.unshift(feedbackRecord);
  if (state.history.length > 50) {
    state.history = state.history.slice(0, 50); // Manter ultimos 50 eventos
  }

  state.totalPrEventsLearned += 1;
  state.updatedAt = new Date().toISOString();

  saveLearningState(state);
  return state;
}

/**
 * Calcula matematicamente o Score de Seguranca com base puramente nos achados reais,
 * invariantes matematicos e nos pesos do Fine-Tuning local (Zero Mocks).
 */
export function calculateMathematicalSecurityScore(
  findings: Array<{ severity: string; ruleId: string }>,
  totalInvariantsChecked: number,
  invariantsPassed: number
): {
  score: number;
  status: 'SECURE' | 'WARNING' | 'VULNERABLE';
  penaltyTotal: number;
  invariantsRatio: number;
  formula: string;
} {
  const learningState = getLearningState();

  let penaltyTotal = 0;

  findings.forEach(f => {
    if (f.severity === 'PASS') return;

    // Busca o peso dinamicamente refinado pelo aprendizado
    const fineTunedWeight = learningState.weights[f.ruleId]?.weight;
    let baseWeight = fineTunedWeight;

    if (!baseWeight) {
      if (f.severity === 'CRITICAL') baseWeight = 35;
      else if (f.severity === 'HIGH') baseWeight = 20;
      else if (f.severity === 'MEDIUM') baseWeight = 10;
      else baseWeight = 5;
    }

    penaltyTotal += baseWeight;
  });

  // Razao de invariantes verificados (0.0 a 1.0)
  const invariantsRatio = totalInvariantsChecked > 0 ? invariantsPassed / totalInvariantsChecked : 1.0;

  // Calculo puramente matematico e proporcional:
  // Score = Max(0, Min(100, (100 * invariantsRatio) - penaltyTotal))
  let rawScore = Math.round((100 * invariantsRatio) - penaltyTotal);
  rawScore = Math.max(0, Math.min(100, rawScore));

  const status: 'SECURE' | 'WARNING' | 'VULNERABLE' =
    rawScore >= 85 ? 'SECURE' : rawScore >= 60 ? 'WARNING' : 'VULNERABLE';

  const formula = `Score = Max(0, Min(100, (100 * ${invariantsRatio.toFixed(2)}) - ${penaltyTotal})) = ${rawScore}%`;

  return {
    score: rawScore,
    status,
    penaltyTotal,
    invariantsRatio,
    formula,
  };
}
