/**
 * Solana Property-Based Fuzzer Vector Generator & Anomaly Injector
 * Module: src/utils/fuzzer.ts
 */

export const U64_MAX = 18446744073709551615n;
export const U64_HALF = 9223372036854775807n;

export type FuzzVectorCategory = 
  | 'EXTREME_NUMERICAL_BOUNDARY'
  | 'ARITHMETIC_OVERFLOW_ATTACK'
  | 'SIGNER_SPOOFING_ANOMALY'
  | 'ZERO_BALANCE_ACCOUNT'
  | 'INVALID_SEED_COLLISION'
  | 'OFF_CURVE_PDA_BUMP'
  | 'LAMPORT_DRAINAGE_SIMULATION';

export interface FuzzTestVector {
  id: number;
  category: FuzzVectorCategory;
  inputs: {
    initialCount: bigint;
    operation: 'increment' | 'decrement' | 'reset' | 'close';
    amount: bigint;
    signerIsAuthority: boolean;
    accountLamports: number;
    bumpSeed: number;
    seeds: string[];
  };
  expectedBehavior: 'SUCCESS' | 'EXPECTED_REVERT' | 'SECURITY_VIOLATION';
  expectedErrorCode?: string;
  description: string;
}

/**
 * Generates batches of high-entropy, boundary-focused test vectors for property fuzzing
 */
export function generateFuzzBatch(batchSize: number = 10000): FuzzTestVector[] {
  const vectors: FuzzTestVector[] = [];

  // Extreme boundaries seed bank
  const boundaryNumbers: bigint[] = [
    0n,
    1n,
    2n,
    255n,
    65535n,
    4294967295n, // u32 max
    U64_HALF,
    U64_MAX - 1000n,
    U64_MAX - 1n,
    U64_MAX,
  ];

  for (let i = 0; i < batchSize; i++) {
    const mod = i % 7;

    if (mod === 0) {
      // 1. Extreme numerical boundary & u64::MAX overflow
      const initVal = boundaryNumbers[i % boundaryNumbers.length];
      const addVal = (i % 2 === 0) ? 1n : U64_MAX;
      const willOverflow = (initVal > U64_MAX - addVal);

      vectors.push({
        id: i + 1,
        category: 'ARITHMETIC_OVERFLOW_ATTACK',
        inputs: {
          initialCount: initVal,
          operation: 'increment',
          amount: addVal,
          signerIsAuthority: true,
          accountLamports: 1231920,
          bumpSeed: 254,
          seeds: ['counter', 'valid_authority_pubkey'],
        },
        expectedBehavior: willOverflow ? 'EXPECTED_REVERT' : 'SUCCESS',
        expectedErrorCode: willOverflow ? 'SecurityErrorCode::NumericalOverflow' : undefined,
        description: `Incrementing ${initVal} by ${addVal}. Overflow anticipated: ${willOverflow}`,
      });
    } else if (mod === 1) {
      // 2. Arithmetic underflow test
      const initVal = (i % 3 === 0) ? 0n : 5n;
      const subVal = 10n;
      const willUnderflow = initVal < subVal;

      vectors.push({
        id: i + 1,
        category: 'EXTREME_NUMERICAL_BOUNDARY',
        inputs: {
          initialCount: initVal,
          operation: 'decrement',
          amount: subVal,
          signerIsAuthority: true,
          accountLamports: 1231920,
          bumpSeed: 254,
          seeds: ['counter', 'valid_authority_pubkey'],
        },
        expectedBehavior: willUnderflow ? 'EXPECTED_REVERT' : 'SUCCESS',
        expectedErrorCode: willUnderflow ? 'SecurityErrorCode::NumericalUnderflow' : undefined,
        description: `Decrementing ${initVal} by ${subVal}. Underflow anticipated: ${willUnderflow}`,
      });
    } else if (mod === 2) {
      // 3. Signer spoofing anomaly (Attacker passes their own wallet to touch victim's counter)
      vectors.push({
        id: i + 1,
        category: 'SIGNER_SPOOFING_ANOMALY',
        inputs: {
          initialCount: 50n,
          operation: 'increment',
          amount: 1n,
          signerIsAuthority: false, // Spoofed attacker!
          accountLamports: 1231920,
          bumpSeed: 254,
          seeds: ['counter', 'victim_authority_pubkey'],
        },
        expectedBehavior: 'EXPECTED_REVERT',
        expectedErrorCode: 'SecurityErrorCode::UnauthorizedAuthority',
        description: 'Impersonation attack: Signer does not match stored authority pubkey.',
      });
    } else if (mod === 3) {
      // 4. Zero balance account anomaly
      vectors.push({
        id: i + 1,
        category: 'ZERO_BALANCE_ACCOUNT',
        inputs: {
          initialCount: 0n,
          operation: 'increment',
          amount: 1n,
          signerIsAuthority: true,
          accountLamports: 0, // Zero balance! Rent violation!
          bumpSeed: 254,
          seeds: ['counter', 'valid_authority_pubkey'],
        },
        expectedBehavior: 'EXPECTED_REVERT',
        expectedErrorCode: 'ProgramError::AccountNotRentExempt',
        description: 'Zero balance account supplied. SVM rent enforcement expected.',
      });
    } else if (mod === 4) {
      // 5. Invalid PDA bump seed
      const invalidBump = (i % 250) + 1; // Not canonical bump
      vectors.push({
        id: i + 1,
        category: 'OFF_CURVE_PDA_BUMP',
        inputs: {
          initialCount: 10n,
          operation: 'increment',
          amount: 1n,
          signerIsAuthority: true,
          accountLamports: 1231920,
          bumpSeed: invalidBump === 254 ? 200 : invalidBump,
          seeds: ['counter', 'valid_authority_pubkey'],
        },
        expectedBehavior: 'EXPECTED_REVERT',
        expectedErrorCode: 'SecurityErrorCode::InvalidBumpSeed',
        description: `Non-canonical bump seed ${invalidBump} injected into constraint validator.`,
      });
    } else if (mod === 5) {
      // 6. Seed collision anomaly
      vectors.push({
        id: i + 1,
        category: 'INVALID_SEED_COLLISION',
        inputs: {
          initialCount: 10n,
          operation: 'increment',
          amount: 1n,
          signerIsAuthority: true,
          accountLamports: 1231920,
          bumpSeed: 254,
          seeds: ['malicious_seed_prefix', 'random_key'],
        },
        expectedBehavior: 'EXPECTED_REVERT',
        expectedErrorCode: 'ProgramError::InvalidSeeds',
        description: 'Seed mismatch: Expected b"counter", supplied altered seed array.',
      });
    } else {
      // 7. Lamport drainage simulation on close instruction
      const isOwner = (i % 5 !== 0);
      vectors.push({
        id: i + 1,
        category: 'LAMPORT_DRAINAGE_SIMULATION',
        inputs: {
          initialCount: 100n,
          operation: 'close',
          amount: 0n,
          signerIsAuthority: isOwner,
          accountLamports: 1231920,
          bumpSeed: 254,
          seeds: ['counter', 'valid_authority_pubkey'],
        },
        expectedBehavior: isOwner ? 'SUCCESS' : 'EXPECTED_REVERT',
        expectedErrorCode: isOwner ? undefined : 'SecurityErrorCode::UnauthorizedAuthority',
        description: `Account close drainage check. Signer is owner: ${isOwner}.`,
      });
    }
  }

  return vectors;
}
