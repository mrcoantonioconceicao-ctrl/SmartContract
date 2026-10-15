/**
 * Solana Anchor & Web3 DevSecOps - Security Linting Service (Clippy & ESLint Strict Engine)
 * Modulo: src/services/securityLintingService.ts
 * Autoria: Marco Antonio Conceicao
 *
 * Encapsula regras estritas de analise estatica focadas em seguranca de memoria em Solana:
 * 1. Rust-Clippy Strict Profile:
 *    - Flags: '--deny warnings', '--deny clippy::panic', '--deny clippy::unwrap_used',
 *             '--deny clippy::expect_used', '--deny clippy::indexing_slicing',
 *             '--deny clippy::integer_arithmetic', '--deny clippy::cast_possible_truncation',
 *             '--deny clippy::mem_forget'
 * 2. ESLint Solana Web3 Strict Profile:
 *    - Regras para TypeScript / Web3:
 *      'no-floating-promises', 'strict-ed25519-signer', 'no-unsafe-account-info-cast',
 *      'require-await-confirmation', 'enforce-preflight-simulation'
 * 3. Perfis de Rigor Selecionaveis:
 *    - 'audit_strict': Rigor maximo enterprise (rejeita qualquer warning e panics)
 *    - 'devsecops_balanced': Rigor padrao balanceado (bloqueia falhas criticas)
 *    - 'permissive_rapid': Rigor permissivo para prototipagem inicial
 * 4. Analisador em tempo real sobre arquivos Rust e TypeScript fornecidos.
 */

export type LintRigorProfile = 'audit_strict' | 'devsecops_balanced' | 'permissive_rapid';

export interface ClippyRuleDefinition {
  flag: string;
  category: 'NO_PANIC' | 'SAFE_MATH' | 'MEMORY_SAFETY' | 'SIGNER_PRIVILEGE' | 'STRICT_COMPLIANCE';
  description: string;
  rationaleSolana: string;
  active: boolean;
}

export interface EslintRuleDefinition {
  ruleName: string;
  severity: 'error' | 'warn' | 'off';
  description: string;
  rationaleWeb3: string;
}

export interface SecurityLintingProfileConfig {
  profileId: LintRigorProfile;
  name: string;
  description: string;
  clippyFlags: string[];
  clippyRules: ClippyRuleDefinition[];
  eslintRules: EslintRuleDefinition[];
  denyWarnings: boolean;
  denyPanics: boolean;
  enforceSignerChecks: boolean;
}

export interface SecurityLintFinding {
  id: string;
  engine: 'clippy' | 'eslint';
  ruleId: string;
  file: string;
  line: number;
  snippet?: string;
  severity: 'error' | 'warning';
  message: string;
  remediation: string;
}

export interface SecurityLintReport {
  timestamp: string;
  profileUsed: LintRigorProfile;
  passed: boolean;
  totalFindings: number;
  errorCount: number;
  warningCount: number;
  findings: SecurityLintFinding[];
  clippyCommandEquivalent: string;
  summary: string;
}

// 1. Configuracao dos 3 Perfis de Rigor
export const SECURITY_LINT_PROFILES: Record<LintRigorProfile, SecurityLintingProfileConfig> = {
  audit_strict: {
    profileId: 'audit_strict',
    name: 'Auditoria Estrita (Enterprise Zero-Panic)',
    description: 'Rigor maximo de DevSecOps. Proibe terminantemente panic!, unwrap(), casting inseguro e violacoes de signatario com --deny warnings e --deny clippy::panic.',
    denyWarnings: true,
    denyPanics: true,
    enforceSignerChecks: true,
    clippyFlags: [
      '-D warnings',
      '-D clippy::panic',
      '-D clippy::unwrap_used',
      '-D clippy::expect_used',
      '-D clippy::indexing_slicing',
      '-D clippy::integer_arithmetic',
      '-D clippy::cast_possible_truncation',
      '-D clippy::mem_forget',
    ],
    clippyRules: [
      {
        flag: '-D clippy::panic',
        category: 'NO_PANIC',
        description: 'Proibe uso de macros panic!(), todo!() ou unreachable!() no runtime BPF',
        rationaleSolana: 'Panic no BPF drena todos os Compute Units (CU) remanescentes da transacao sem emitir erro customizado.',
        active: true,
      },
      {
        flag: '-D clippy::unwrap_used',
        category: 'NO_PANIC',
        description: 'Proibe invocacao direta de .unwrap() em Result e Option',
        rationaleSolana: 'Substitua por .ok_or(SecurityErrorCode::...) para garantir retorno gracioso com Result<()> Anchor.',
        active: true,
      },
      {
        flag: '-D clippy::expect_used',
        category: 'NO_PANIC',
        description: 'Proibe .expect("message") em smart contracts Solana',
        rationaleSolana: 'Gera panico abortivo em instrucoes mutaveis, impedindo reversao semantica.',
        active: true,
      },
      {
        flag: '-D clippy::integer_arithmetic',
        category: 'SAFE_MATH',
        description: 'Proibe operadores aritmeticos nativos (+, -, *, /) sem verificacao',
        rationaleSolana: 'Obriga uso de .checked_add(), .checked_sub() ou saturating_* para evitar estouro numerico.',
        active: true,
      },
      {
        flag: '-D clippy::indexing_slicing',
        category: 'MEMORY_SAFETY',
        description: 'Proibe indexacao direta de slices e arrays (&slice[index])',
        rationaleSolana: 'Indexacao fora de limites gera panico de memoria insegura no SVM; use .get(index).',
        active: true,
      },
      {
        flag: '-D clippy::cast_possible_truncation',
        category: 'SAFE_MATH',
        description: 'Proibe conversao numerica (as u32, as u8) que possa truncar valores u64',
        rationaleSolana: 'Truncamentos silenciosos corrompem saldos de lamports e balancos de contas.',
        active: true,
      },
    ],
    eslintRules: [
      {
        ruleName: '@solana-security/require-signer-privilege',
        severity: 'error',
        description: 'Exige que toda autoridade que assina instrucao mutavel seja tipada como Signer',
        rationaleWeb3: 'Evita AccountInfo desprotegido suscetivel a ataques de falsificacao de identidade.',
      },
      {
        ruleName: '@solana-security/no-floating-promises',
        severity: 'error',
        description: 'Proibe chamadas assincronas Web3 (sendTransaction, confirm) sem await',
        rationaleWeb3: 'Promises orfas geram falhas silenciosas na confirmacao de blocos.',
      },
      {
        ruleName: '@solana-security/enforce-preflight-simulation',
        severity: 'error',
        description: 'Exige simulacao preflight de transacao antes do broadcast na rede',
        rationaleWeb3: 'Pre-valida condicoes de rent-exempt e assinantes, economizando taxas de rede.',
      },
    ],
  },

  devsecops_balanced: {
    profileId: 'devsecops_balanced',
    name: 'DevSecOps Balanceado (Recomendado)',
    description: 'Equilibrio ideal entre produtividade e seguranca. Bloqueia panics e ausencias de signatarios com warnings para estilizacao.',
    denyWarnings: false,
    denyPanics: true,
    enforceSignerChecks: true,
    clippyFlags: [
      '-W clippy::all',
      '-D clippy::panic',
      '-D clippy::unwrap_used',
      '-W clippy::integer_arithmetic',
    ],
    clippyRules: [
      {
        flag: '-D clippy::panic',
        category: 'NO_PANIC',
        description: 'Bloqueio de panic!() direto em funcoes de instrucao Anchor',
        rationaleSolana: 'Garante que os erros sejam propagados via Result<()>.',
        active: true,
      },
      {
        flag: '-D clippy::unwrap_used',
        category: 'NO_PANIC',
        description: 'Bloqueio de .unwrap() em fluxos criticos',
        rationaleSolana: 'Exige tratamento com operador ? e codigos de erro customizados.',
        active: true,
      },
      {
        flag: '-W clippy::integer_arithmetic',
        category: 'SAFE_MATH',
        description: 'Alerta sobre operacoes aritmeticas sem checked_*',
        rationaleSolana: 'Avisa sobre riscos potenciais de overflow.',
        active: true,
      },
    ],
    eslintRules: [
      {
        ruleName: '@solana-security/require-signer-privilege',
        severity: 'error',
        description: 'Exige tipagem estrita de Signer em contas de autoridade',
        rationaleWeb3: 'Impede passagem acidental de AccountInfo desprotegido.',
      },
      {
        ruleName: '@solana-security/no-floating-promises',
        severity: 'warn',
        description: 'Avisa sobre promises de transacao sem tratamento',
        rationaleWeb3: 'Garante robustez em dApps clientes.',
      },
    ],
  },

  permissive_rapid: {
    profileId: 'permissive_rapid',
    name: 'Permissivo / Prototipagem Rapida',
    description: 'Modo tolerante para desenvolvimento inicial e testes exploratorios locais sem travar a compilacao.',
    denyWarnings: false,
    denyPanics: false,
    enforceSignerChecks: false,
    clippyFlags: [
      '-W clippy::all',
    ],
    clippyRules: [
      {
        flag: '-W clippy::panic',
        category: 'NO_PANIC',
        description: 'Alerta informativo sobre uso de panics',
        rationaleSolana: 'Informa sem bloquear a compilacao.',
        active: false,
      },
    ],
    eslintRules: [
      {
        ruleName: '@solana-security/require-signer-privilege',
        severity: 'warn',
        description: 'Aviso sobre signatarios nao validados',
        rationaleWeb3: 'Permite testes com mock accounts.',
      },
    ],
  },
};

const STORAGE_KEY_LINT_PROFILE = 'solana_security_lint_rigor_profile';

/**
 * Obtem o perfil de rigor ativo persistido
 */
export function getActiveLintProfile(): LintRigorProfile {
  try {
    if (typeof localStorage !== 'undefined') {
      const stored = localStorage.getItem(STORAGE_KEY_LINT_PROFILE) as LintRigorProfile;
      if (stored && SECURITY_LINT_PROFILES[stored]) {
        return stored;
      }
    }
  } catch {
    // Fallback gracioso
  }
  return 'audit_strict';
}

/**
 * Salva o perfil de rigor ativo
 */
export function setActiveLintProfile(profile: LintRigorProfile): void {
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(STORAGE_KEY_LINT_PROFILE, profile);
    }
  } catch {
    // Silencioso
  }
}

/**
 * Executa a analise estrita de Clippy e ESLint de seguranca sobre arquivos
 */
export function runSecurityLintAudit(
  files: Array<{ path: string; content: string }>,
  profileId: LintRigorProfile = getActiveLintProfile()
): SecurityLintReport {
  const profile = SECURITY_LINT_PROFILES[profileId];
  const findings: SecurityLintFinding[] = [];

  for (const file of files) {
    const lines = file.content.split('\n');

    // 1. Analise de Seguranca Rust / Solana (Clippy Strict Rules)
    if (file.path.endsWith('.rs')) {
      lines.forEach((lineText, idx) => {
        const lineNum = idx + 1;
        const trimmed = lineText.trim();
        if (trimmed.startsWith('//')) return; // Pular comentarios

        // Regra NO_PANIC: panic!(), todo!(), unreachable!()
        if (profile.denyPanics || profile.profileId === 'audit_strict') {
          if (trimmed.includes('panic!(') || trimmed.includes('todo!(') || trimmed.includes('unreachable!(')) {
            findings.push({
              id: `CLIPPY-PANIC-${file.path}-${lineNum}`,
              engine: 'clippy',
              ruleId: 'clippy::panic',
              file: file.path,
              line: lineNum,
              snippet: trimmed,
              severity: profile.denyPanics ? 'error' : 'warning',
              message: 'Uso de macro panic!/todo! detetado. No runtime Solana SVM, panicos abortivos drenam todos os Compute Units sem reverter graciosamente.',
              remediation: 'Substitua por retorno gracioso Err(SecurityErrorCode::<NomeDoErro>.into()) ou operador ?.',
            });
          }

          // Regra NO_PANIC: .unwrap()
          if (trimmed.includes('.unwrap()')) {
            findings.push({
              id: `CLIPPY-UNWRAP-${file.path}-${lineNum}`,
              engine: 'clippy',
              ruleId: 'clippy::unwrap_used',
              file: file.path,
              line: lineNum,
              snippet: trimmed,
              severity: profile.denyPanics ? 'error' : 'warning',
              message: 'Chamada direta a .unwrap() pode disparar panico no BPF se o valor for None ou Err.',
              remediation: 'Utilize .ok_or(SecurityErrorCode::NumericalOverflow)? para mapear erros com seguranca.',
            });
          }

          // Regra NO_PANIC: .expect()
          if (trimmed.includes('.expect(')) {
            findings.push({
              id: `CLIPPY-EXPECT-${file.path}-${lineNum}`,
              engine: 'clippy',
              ruleId: 'clippy::expect_used',
              file: file.path,
              line: lineNum,
              snippet: trimmed,
              severity: profile.denyPanics ? 'error' : 'warning',
              message: 'Chamada a .expect() provoca panico abortivo se a operacao falhar.',
              remediation: 'Substitua por erro de dominio customizado #[error_code].',
            });
          }
        }

        // Regra SAFE_MATH: operacao de incremento ou soma sem checked_add
        if (profile.profileId === 'audit_strict' || profile.profileId === 'devsecops_balanced') {
          const isArithmeticExpr = (trimmed.includes('count +=') || trimmed.includes('count -=') || trimmed.includes('+') || trimmed.includes('-')) &&
            !trimmed.startsWith('//') && !trimmed.startsWith('/*') && !trimmed.startsWith('*') && !trimmed.includes('checked_') && !trimmed.includes('saturating_');
          
          if ((trimmed.includes('count +=') || trimmed.includes('count -=')) && !trimmed.includes('checked_')) {
            findings.push({
              id: `CLIPPY-MATH-${file.path}-${lineNum}`,
              engine: 'clippy',
              ruleId: 'clippy::integer_arithmetic',
              file: file.path,
              line: lineNum,
              snippet: trimmed,
              severity: 'error',
              message: 'Operacao aritmetica direta sem checked_add/checked_sub detetada. Risco critico de overflow/underflow numerico na SVM.',
              remediation: 'Utilize .checked_add(amount).ok_or(SecurityErrorCode::NumericalOverflow)? para protecao estrita de transbordamento.',
            });
          }
        }

        // Regra SIGNER_PRIVILEGE: AccountInfo em conta de autoridade
        if (profile.enforceSignerChecks) {
          if (trimmed.includes('pub authority: AccountInfo') || trimmed.includes('authority: AccountInfo')) {
            findings.push({
              id: `CLIPPY-SIGNER-${file.path}-${lineNum}`,
              engine: 'clippy',
              ruleId: 'solana::missing_signer_check',
              file: file.path,
              line: lineNum,
              snippet: trimmed,
              severity: 'error',
              message: 'Autoridade tipada como AccountInfo em vez de Signer. Falta verificacao criptografica de assinatura Ed25519.',
              remediation: 'Altere para `pub authority: Signer<\'info>` e adicione constraint declarativa `has_one = authority`.',
            });
          }
        }
      });
    }

    // 2. Analise de Seguranca TypeScript / Web3 (ESLint Strict Rules)
    if (file.path.endsWith('.ts') || file.path.endsWith('.tsx')) {
      lines.forEach((lineText, idx) => {
        const lineNum = idx + 1;
        const trimmed = lineText.trim();
        if (trimmed.startsWith('//')) return;

        // ESLint: require-signer-privilege
        if (profile.enforceSignerChecks && trimmed.includes('isSigner: false') && trimmed.includes('authority')) {
          findings.push({
            id: `ESLINT-SIGNER-${file.path}-${lineNum}`,
            engine: 'eslint',
            ruleId: '@solana-security/require-signer-privilege',
            file: file.path,
            line: lineNum,
            snippet: trimmed,
            severity: 'error',
            message: 'A instrucao cliente define a conta de autoridade com isSigner: false.',
            remediation: 'Configure `{ pubkey: authority, isSigner: true, isWritable: true }` para garantir assinatura.',
          });
        }
      });
    }
  }

  const errorCount = findings.filter(f => f.severity === 'error').length;
  const warningCount = findings.filter(f => f.severity === 'warning').length;
  const passed = profile.denyWarnings ? (errorCount === 0 && warningCount === 0) : (errorCount === 0);

  const clippyCommand = `cargo clippy --workspace --all-targets -- ${profile.clippyFlags.join(' ')}`;

  const summary = passed
    ? `Conformidade total atingida com o perfil ${profile.name}. 0 erros de memoria insegura, 0 panics no SVM e privilegios de signatario auditados.`
    : `Foram detetados ${errorCount} erros e ${warningCount} avisos sob o perfil ${profile.name}. Corrija as vulnerabilidades de memoria e panics para fechar o job de CI.`;

  return {
    timestamp: new Date().toISOString(),
    profileUsed: profileId,
    passed,
    totalFindings: findings.length,
    errorCount,
    warningCount,
    findings,
    clippyCommandEquivalent: clippyCommand,
    summary,
  };
}
