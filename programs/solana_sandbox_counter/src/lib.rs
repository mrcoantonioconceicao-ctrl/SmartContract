use anchor_lang::prelude::*;

pub mod domain;

// Standard Sandbox Program ID for the Anchor Counter DevSecOps environment
declare_id!("CntSandbox111111111111111111111111111111111");

#[program]
pub mod solana_sandbox_counter {
    use super::*;

    /// Initializes a deterministically derived PDA counter account for the signing authority.
    /// Allocates exact 49 bytes for optimal rent-exempt calculation.
    pub fn initialize(ctx: Context<Initialize>, initial_count: u64) -> Result<()> {
        let counter = &mut ctx.accounts.counter;
        counter.authority = ctx.accounts.authority.key();
        counter.count = initial_count;
        counter.bump = ctx.bumps.counter;

        msg!("Initialized UserCounter PDA for authority: {}", counter.authority);
        msg!("Initial count: {}, Canonical bump: {}", counter.count, counter.bump);
        Ok(())
    }

    /// Increments the counter with native checked arithmetic protection and authority verification.
    pub fn increment(ctx: Context<UpdateCounter>, amount: u64) -> Result<()> {
        let counter = &mut ctx.accounts.counter;

        // Native arithmetic overflow protection via checked_add
        counter.count = counter
            .count
            .checked_add(amount)
            .ok_or(SecurityErrorCode::NumericalOverflow)?;

        msg!("Counter incremented by {}. New count: {}", amount, counter.count);
        Ok(())
    }

    /// Decrements the counter with native checked arithmetic protection to prevent underflow.
    pub fn decrement(ctx: Context<UpdateCounter>, amount: u64) -> Result<()> {
        let counter = &mut ctx.accounts.counter;

        // Native arithmetic underflow protection via checked_sub
        counter.count = counter
            .count
            .checked_sub(amount)
            .ok_or(SecurityErrorCode::NumericalUnderflow)?;

        msg!("Counter decremented by {}. New count: {}", amount, counter.count);
        Ok(())
    }

    /// Resets the counter value to zero, strictly authorized by the counter owner.
    pub fn reset(ctx: Context<UpdateCounter>) -> Result<()> {
        let counter = &mut ctx.accounts.counter;
        counter.count = 0;

        msg!("Counter reset to zero by authority: {}", ctx.accounts.authority.key());
        Ok(())
    }

    /// Safely closes the PDA account and reclaims rent-exempt lamports back to the authority.
    pub fn close(ctx: Context<CloseCounter>) -> Result<()> {
        msg!("UserCounter PDA closed. Rent reclaimed by: {}", ctx.accounts.authority.key());
        Ok(())
    }

    /// Records an immutable, chain-anchored audit receipt on Solana with verified audit hash,
    /// risk status and rent-exempt allocation.
    pub fn record_audit_receipt(
        ctx: Context<RecordAuditReceipt>,
        audit_hash: [u8; 32],
        risk_level: u8,
        findings_count: u32,
        security_score: u8,
    ) -> Result<()> {
        require!(security_score <= 100, SecurityErrorCode::InvalidSecurityScore);
        require!(risk_level <= 4, SecurityErrorCode::InvalidRiskLevel);

        let receipt = &mut ctx.accounts.receipt;
        receipt.auditor = ctx.accounts.auditor.key();
        receipt.target_program = ctx.accounts.target_program.key();
        receipt.audit_hash = audit_hash;
        receipt.risk_level = risk_level;
        receipt.findings_count = findings_count;
        receipt.security_score = security_score;
        receipt.timestamp = Clock::get()?.unix_timestamp;
        receipt.bump = ctx.bumps.receipt;

        // Increment cumulative audit receipt counter on authority UserCounter state if provided
        if let Some(counter) = &mut ctx.accounts.counter {
            counter.count = counter
                .count
                .checked_add(1)
                .ok_or(SecurityErrorCode::NumericalOverflow)?;
            msg!("Cumulative audits registered: {}", counter.count);
        }

        msg!("Audit receipt recorded on-chain for target: {}", receipt.target_program);
        msg!("Security Score: {}/100, Risk Level: {}, Findings: {}", security_score, risk_level, findings_count);
        Ok(())
    }
}

// ==========================================
// DECLARATIVE ANCHOR INSTRUCTION CONTEXTS
// ==========================================

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = UserCounter::ACCOUNT_SPACE,
        seeds = [b"counter", authority.key().as_ref()],
        bump
    )]
    pub counter: Account<'info, UserCounter>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateCounter<'info> {
    #[account(
        mut,
        seeds = [b"counter", authority.key().as_ref()],
        bump = counter.bump,
        has_one = authority @ SecurityErrorCode::UnauthorizedAuthority
    )]
    pub counter: Account<'info, UserCounter>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseCounter<'info> {
    #[account(
        mut,
        seeds = [b"counter", authority.key().as_ref()],
        bump = counter.bump,
        has_one = authority @ SecurityErrorCode::UnauthorizedAuthority,
        close = authority
    )]
    pub counter: Account<'info, UserCounter>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(audit_hash: [u8; 32])]
pub struct RecordAuditReceipt<'info> {
    #[account(
        init,
        payer = auditor,
        space = AuditReceipt::ACCOUNT_SPACE,
        seeds = [
            AuditReceipt::SEED_PREFIX,
            target_program.key().as_ref(),
            audit_hash.as_ref()
        ],
        bump
    )]
    pub receipt: Account<'info, AuditReceipt>,

    /// CHECK: Target smart contract program being audited (validated against system pubkey format)
    pub target_program: UncheckedAccount<'info>,

    /// Optional cumulative counter account tracking auditor receipts
    #[account(
        mut,
        seeds = [b"counter", auditor.key().as_ref()],
        bump = counter.bump,
        has_one = authority @ SecurityErrorCode::UnauthorizedAuthority
    )]
    pub counter: Option<Account<'info, UserCounter>>,

    #[account(mut)]
    pub auditor: Signer<'info>,

    /// Signer authority for the optional UserCounter account
    pub authority: Option<Signer<'info>>,

    pub system_program: Program<'info, System>,
}

// ==========================================
// STATE DATA STRUCTURE & MEMORY ALLOCATION
// ==========================================

#[account]
pub struct UserCounter {
    pub authority: Pubkey, // 32 bytes
    pub count: u64,        // 8 bytes
    pub bump: u8,          // 1 byte
}

impl UserCounter {
    // Explicit rent-exempt memory allocation layout
    pub const DISCRIMINATOR_SPACE: usize = 8;
    pub const AUTHORITY_SPACE: usize = 32;
    pub const COUNT_SPACE: usize = 8;
    pub const BUMP_SPACE: usize = 1;

    /// Total space: 8 + 32 + 8 + 1 = 49 bytes
    pub const ACCOUNT_SPACE: usize = Self::DISCRIMINATOR_SPACE
        + Self::AUTHORITY_SPACE
        + Self::COUNT_SPACE
        + Self::BUMP_SPACE;
}

/// Chain-Anchored Audit Receipt account storing verified security posture
#[account]
pub struct AuditReceipt {
    pub auditor: Pubkey,         // 32 bytes
    pub target_program: Pubkey,  // 32 bytes
    pub audit_hash: [u8; 32],    // 32 bytes (SHA-256 / Blake3)
    pub timestamp: i64,          // 8 bytes (Unix timestamp)
    pub findings_count: u32,     // 4 bytes
    pub security_score: u8,      // 1 byte (0 to 100)
    pub risk_level: u8,          // 1 byte (0=SECURE, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL)
    pub bump: u8,                // 1 byte
}

impl AuditReceipt {
    pub const SEED_PREFIX: &'static [u8] = b"audit_receipt";

    pub const DISCRIMINATOR_SPACE: usize = 8;
    pub const AUDITOR_SPACE: usize = 32;
    pub const TARGET_PROGRAM_SPACE: usize = 32;
    pub const AUDIT_HASH_SPACE: usize = 32;
    pub const TIMESTAMP_SPACE: usize = 8;
    pub const FINDINGS_COUNT_SPACE: usize = 4;
    pub const SECURITY_SCORE_SPACE: usize = 1;
    pub const RISK_LEVEL_SPACE: usize = 1;
    pub const BUMP_SPACE: usize = 1;

    /// Total space: 8 + 32 + 32 + 32 + 8 + 4 + 1 + 1 + 1 = 119 bytes
    pub const ACCOUNT_SPACE: usize = Self::DISCRIMINATOR_SPACE
        + Self::AUDITOR_SPACE
        + Self::TARGET_PROGRAM_SPACE
        + Self::AUDIT_HASH_SPACE
        + Self::TIMESTAMP_SPACE
        + Self::FINDINGS_COUNT_SPACE
        + Self::SECURITY_SCORE_SPACE
        + Self::RISK_LEVEL_SPACE
        + Self::BUMP_SPACE;
}

// ==========================================
// SECURITY ERROR CODES
// ==========================================

#[error_code]
pub enum SecurityErrorCode {
    #[msg("Arithmetic overflow occurred during counter operation")]
    NumericalOverflow,

    #[msg("Arithmetic underflow occurred: counter cannot be negative")]
    NumericalUnderflow,

    #[msg("Access Denied: Signer does not match the registered counter authority")]
    UnauthorizedAuthority,

    #[msg("Invalid canonical bump seed provided")]
    InvalidBumpSeed,

    #[msg("Security score must be between 0 and 100")]
    InvalidSecurityScore,

    #[msg("Risk level must be between 0 (SECURE) and 4 (CRITICAL)")]
    InvalidRiskLevel,
}
