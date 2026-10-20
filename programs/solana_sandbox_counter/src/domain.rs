//! Domain-Driven Design (DDD) - Bounded Context: Solana UserCounter & Batch Audit
//! Modulo: programs/solana_sandbox_counter/src/domain.rs
//! Autoria: Marco Antonio Conceicao
//!
//! Modulo complementar e incremental (Regra C44 - Nao-Destrutiva).
//! Define a raiz de agregacao (Aggregate Root), especificacoes de invariantes
//! e servicos de dominio para o smart contract UserCounter e recibos de auditoria em lote.

use anchor_lang::prelude::*;

/// Raiz de Agregacao (Aggregate Root) no contexto DDD
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq)]
pub struct UserCounterAggregate {
    pub authority: Pubkey,
    pub count: u64,
    pub bump: u8,
}

/// Especificacao formal de invariantes do agregado UserCounter
pub struct UserCounterDomainSpec;

impl UserCounterDomainSpec {
    /// Invariante DDD INV-RENT-EXEMPT:
    /// O espaco alocado deve ser exatamente 49 bytes (8 disc + 32 auth + 8 count + 1 bump)
    pub const EXACT_ACCOUNT_SPACE: usize = 8 + 32 + 8 + 1;

    /// Invariante DDD INV-DETERMINISTIC-PDA:
    /// Prefixo canonico de semente para derivacao deterministica da conta
    pub const SEED_PREFIX: &'static [u8] = b"counter";

    /// Valida se uma transicao de incremento preserva o invariante de nao-estouro (checked arithmetic)
    pub fn validate_increment_invariant(current: u64, amount: u64) -> Result<u64> {
        current.checked_add(amount).ok_or_else(|| {
            error!(crate::SecurityErrorCode::NumericalOverflow)
        })
    }

    /// Valida se uma transicao de decremento preserva o invariante de nao-negatividade
    pub fn validate_decrement_invariant(current: u64, amount: u64) -> Result<u64> {
        current.checked_sub(amount).ok_or_else(|| {
            error!(crate::SecurityErrorCode::NumericalUnderflow)
        })
    }

    /// Valida se a autoridade informada corresponde estritamente ao proprietario do agregado
    pub fn validate_authority_invariant(registered: &Pubkey, signer: &Pubkey) -> bool {
        registered == signer
    }
}

/// Item de entrada para recibo de auditoria em lote (Batch Audit Item)
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq)]
pub struct AuditReceiptItemInput {
    pub target_program: Pubkey,
    pub audit_hash: [u8; 32],
    pub risk_level: u8,
    pub findings_count: u32,
    pub security_score: u8,
}

/// Especificacao formal de invariantes para atestado de auditoria em lote (Batch Audit Spec)
pub struct BatchAuditDomainSpec;

impl BatchAuditDomainSpec {
    /// Limite maximo de recibos processados em lote por transacao atomica (otimizacao de Compute Units)
    pub const MAX_BATCH_SIZE: usize = 5;

    /// Prefixo canonico de semente para o PDA do resumo de auditoria em lote
    pub const SEED_PREFIX: &'static [u8] = b"batch_audit";

    /// Espaco exato alocado para a struct BatchAuditSummary (88 bytes)
    /// 8 disc + 32 auditor + 32 batch_id + 1 count + 4 findings + 1 avg_score + 1 max_risk + 8 ts + 1 bump = 88 bytes
    pub const EXACT_ACCOUNT_SPACE: usize = 8 + 32 + 32 + 1 + 4 + 1 + 1 + 8 + 1;

    /// Valida se o tamanho do lote esta no intervalo permitido [1, 5]
    pub fn validate_batch_size(size: usize) -> bool {
        size > 0 && size <= Self::MAX_BATCH_SIZE
    }

    /// Valida se a pontuacao de seguranca esta no intervalo [0, 100]
    pub fn validate_security_score(score: u8) -> bool {
        score <= 100
    }

    /// Valida se o nivel de risco esta no intervalo [0, 4]
    pub fn validate_risk_level(risk: u8) -> bool {
        risk <= 4
    }
}
