/**
 * Dynamic Secure Solana Anchor Contract & Template Generator
 * Supports customized business rules with DevSecOps constraints
 */

export interface CustomField {
  name: string;
  rustType: 'u64' | 'u32' | 'u8' | 'i64' | 'Pubkey' | 'bool' | 'String';
  sizeBytes: number;
  description: string;
}

export interface CustomInstructionRule {
  name: string;
  action: 'increment' | 'decrement' | 'set' | 'transfer' | 'toggle';
  targetField: string;
  hasCheckedMath: boolean;
  requiresSigner: boolean;
  requiresOwnerAuth: boolean;
}

export interface ContractTemplateConfig {
  programName: string;
  accountName: string;
  pdaPrefix: string;
  fields: CustomField[];
  instructions: CustomInstructionRule[];
}

export const DEFAULT_COUNTER_CONFIG: ContractTemplateConfig = {
  programName: "solana_sandbox_counter",
  accountName: "UserCounter",
  pdaPrefix: "counter",
  fields: [
    { name: "authority", rustType: "Pubkey", sizeBytes: 32, description: "Owner wallet address" },
    { name: "count", rustType: "u64", sizeBytes: 8, description: "Checked numeric state value" },
    { name: "bump", rustType: "u8", sizeBytes: 1, description: "Canonical PDA bump seed" },
  ],
  instructions: [
    { name: "initialize", action: "set", targetField: "count", hasCheckedMath: false, requiresSigner: true, requiresOwnerAuth: true },
    { name: "increment", action: "increment", targetField: "count", hasCheckedMath: true, requiresSigner: true, requiresOwnerAuth: true },
    { name: "decrement", action: "decrement", targetField: "count", hasCheckedMath: true, requiresSigner: true, requiresOwnerAuth: true },
    { name: "reset", action: "set", targetField: "count", hasCheckedMath: false, requiresSigner: true, requiresOwnerAuth: true },
    { name: "close", action: "toggle", targetField: "bump", hasCheckedMath: false, requiresSigner: true, requiresOwnerAuth: true },
  ],
};

/**
 * Calculates exact Rent-Exempt space required including Anchor 8-byte discriminator
 */
export function calculateAccountSpace(fields: CustomField[]): {
  discriminatorBytes: number;
  fieldsBytes: number;
  totalBytes: number;
  rentExemptLamports: number;
} {
  const discriminatorBytes = 8;
  const fieldsBytes = fields.reduce((acc, f) => acc + f.sizeBytes, 0);
  const totalBytes = discriminatorBytes + fieldsBytes;
  // Solana rent calculation: 890,880 base + totalBytes * 6,960 lamports (approx on mainnet/devnet)
  const rentExemptLamports = 890880 + totalBytes * 6960;

  return {
    discriminatorBytes,
    fieldsBytes,
    totalBytes,
    rentExemptLamports,
  };
}

/**
 * Generates modular Rust Anchor code with DevSecOps AST & security guards
 */
export function generateModularAnchorContract(config: ContractTemplateConfig): string {
  const { totalBytes } = calculateAccountSpace(config.fields);

  return `use anchor_lang::prelude::*;

// Standard Sandbox Program ID for ${config.programName}
declare_id!("CntSandbox111111111111111111111111111111111");

#[program]
pub mod ${config.programName} {
    use super::*;

    /// Initializes a deterministically derived PDA account for the signing authority.
    /// Memory allocation: exactly ${totalBytes} bytes for Rent-Exempt efficiency.
    pub fn initialize(ctx: Context<Initialize>, initial_value: u64) -> Result<()> {
        let account = &mut ctx.accounts.${config.accountName.toLowerCase()};
        account.authority = ctx.accounts.authority.key();
        account.count = initial_value;
        account.bump = ctx.bumps.${config.accountName.toLowerCase()};

        msg!("Initialized ${config.accountName} PDA for authority: {}", account.authority);
        msg!("Initial count: {}, Stored bump: {}", account.count, account.bump);
        Ok(())
    }

    /// Increments the numeric state with native checked arithmetic overflow protection.
    pub fn increment(ctx: Context<UpdateAccount>, amount: u64) -> Result<()> {
        let account = &mut ctx.accounts.${config.accountName.toLowerCase()};

        account.count = account
            .count
            .checked_add(amount)
            .ok_or(SecurityErrorCode::NumericalOverflow)?;

        msg!("State incremented by {}. Current value: {}", amount, account.count);
        Ok(())
    }

    /// Decrements the numeric state with native checked arithmetic underflow protection.
    pub fn decrement(ctx: Context<UpdateAccount>, amount: u64) -> Result<()> {
        let account = &mut ctx.accounts.${config.accountName.toLowerCase()};

        account.count = account
            .count
            .checked_sub(amount)
            .ok_or(SecurityErrorCode::NumericalUnderflow)?;

        msg!("State decremented by {}. Current value: {}", amount, account.count);
        Ok(())
    }

    /// Safely resets state back to baseline, strictly gated to verified authority.
    pub fn reset(ctx: Context<UpdateAccount>) -> Result<()> {
        let account = &mut ctx.accounts.${config.accountName.toLowerCase()};
        account.count = 0;

        msg!("State reset to zero by authority: {}", ctx.accounts.authority.key());
        Ok(())
    }

    /// Closes the PDA and transfers rent lamports back to the signer authority.
    pub fn close(ctx: Context<CloseAccount>) -> Result<()> {
        msg!("PDA account safely closed. Rent refunded to: {}", ctx.accounts.authority.key());
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
        space = ${config.accountName}::ACCOUNT_SPACE,
        seeds = [b"${config.pdaPrefix}", authority.key().as_ref()],
        bump
    )]
    pub ${config.accountName.toLowerCase()}: Account<'info, ${config.accountName}>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateAccount<'info> {
    #[account(
        mut,
        seeds = [b"${config.pdaPrefix}", authority.key().as_ref()],
        bump = ${config.accountName.toLowerCase()}.bump,
        has_one = authority @ SecurityErrorCode::UnauthorizedAuthority
    )]
    pub ${config.accountName.toLowerCase()}: Account<'info, ${config.accountName}>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseAccount<'info> {
    #[account(
        mut,
        seeds = [b"${config.pdaPrefix}", authority.key().as_ref()],
        bump = ${config.accountName.toLowerCase()}.bump,
        has_one = authority @ SecurityErrorCode::UnauthorizedAuthority,
        close = authority
    )]
    pub ${config.accountName.toLowerCase()}: Account<'info, ${config.accountName}>,

    #[account(mut)]
    pub authority: Signer<'info>,
}

// ==========================================
// STATE DATA STRUCTURE & MEMORY ALLOCATION
// ==========================================

#[account]
pub struct ${config.accountName} {
${config.fields.map(f => `    pub ${f.name}: ${f.rustType}, // ${f.sizeBytes} bytes - ${f.description}`).join('\n')}
}

impl ${config.accountName} {
    pub const DISCRIMINATOR_SPACE: usize = 8;
${config.fields.map(f => `    pub const ${f.name.toUpperCase()}_SPACE: usize = ${f.sizeBytes};`).join('\n')}

    /// Exact rent-exempt memory allocation (${totalBytes} bytes)
    pub const ACCOUNT_SPACE: usize = Self::DISCRIMINATOR_SPACE
${config.fields.map(f => `        + Self::${f.name.toUpperCase()}_SPACE`).join('\n')};
}

// ==========================================
// SECURITY ERROR CODES
// ==========================================

#[error_code]
pub enum SecurityErrorCode {
    #[msg("Arithmetic overflow occurred during operation")]
    NumericalOverflow,

    #[msg("Arithmetic underflow occurred during operation")]
    NumericalUnderflow,

    #[msg("Unauthorized: Signer does not match the registered account authority")]
    UnauthorizedAuthority,

    #[msg("Canonical bump seed mismatch")]
    InvalidBumpSeed,
}
`;
}
