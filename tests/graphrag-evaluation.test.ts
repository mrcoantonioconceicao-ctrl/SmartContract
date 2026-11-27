import assert from 'node:assert/strict';
import { buildContractSecurityGraph } from '../src/services/graphRAGEnterpriseService.ts';
import { hashGraphRagInputs } from '../src/services/graphragCache.ts';

type Detection = 'SIGNER_AUTH' | 'CHECKED_MATH' | 'RENT_EXEMPT';

interface EvaluationCase {
  name: string;
  sourceCode: string;
  expected: Detection[];
}

const cases: EvaluationCase[] = [
  {
    name: 'missing signer and has_one guard',
    sourceCode: `
      pub struct Increment<'info> {
        #[account(mut)]
        pub counter: Account<'info, Counter>,
        pub authority: SystemAccount<'info>,
      }
      counter.count = counter.count.checked_add(amount).ok_or(SecurityErrorCode::NumericalOverflow)?;
      pub const ACCOUNT_SPACE: usize = 49;
    `,
    expected: ['SIGNER_AUTH'],
  },
  {
    name: 'unchecked arithmetic',
    sourceCode: `
      pub struct Increment<'info> {
        pub authority: Signer<'info>,
        #[account(mut, has_one = authority)]
        pub counter: Account<'info, Counter>,
      }
      counter.count = counter.count + amount;
      pub const ACCOUNT_SPACE: usize = 49;
    `,
    expected: ['CHECKED_MATH'],
  },
  {
    name: 'missing exact rent-exempt allocation',
    sourceCode: `
      pub struct Counter {
        pub authority: Pubkey,
        pub count: u64,
        pub bump: u8,
      }
      pub authority: Signer<'info>;
      has_one = authority
      checked_add
      checked_sub
    `,
    expected: ['RENT_EXEMPT'],
  },
  {
    name: 'secure Anchor counter',
    sourceCode: `
      pub struct Increment<'info> {
        pub authority: Signer<'info>,
        #[account(mut, has_one = authority)]
        pub counter: Account<'info, Counter>,
      }
      pub const ACCOUNT_SPACE: usize = 49;
      counter.count = counter.count.checked_add(amount).ok_or(SecurityErrorCode::NumericalOverflow)?;
      counter.count = counter.count.checked_sub(amount).ok_or(SecurityErrorCode::NumericalUnderflow)?;
    `,
    expected: [],
  },
];

function detectedLabels(sourceCode: string): Set<Detection> {
  const graph = buildContractSecurityGraph(sourceCode);
  const detected = new Set<Detection>();
  for (const path of graph.attackPaths) {
    if (path.status !== 'EXPLOITABLE') continue;
    if (/Signer|Privil[eé]gio|Authorization/i.test(path.title)) detected.add('SIGNER_AUTH');
    if (/Inteiros|Overflow|Estouro/i.test(path.title)) detected.add('CHECKED_MATH');
    if (/Lamport|Rent/i.test(path.title)) detected.add('RENT_EXEMPT');
  }
  return detected;
}

let truePositives = 0;
let falsePositives = 0;
let falseNegatives = 0;

for (const evaluationCase of cases) {
  const detected = detectedLabels(evaluationCase.sourceCode);
  const expected = new Set(evaluationCase.expected);
  for (const label of detected) {
    if (expected.has(label)) truePositives += 1;
    else falsePositives += 1;
  }
  for (const label of expected) {
    if (!detected.has(label)) falseNegatives += 1;
  }
  assert.deepEqual(
    [...detected].sort(),
    [...expected].sort(),
    `GraphRAG detection mismatch: ${evaluationCase.name}`,
  );
}

const precision = truePositives / (truePositives + falsePositives);
const recall = truePositives / (truePositives + falseNegatives);
const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);

const cachedSourceHash = hashGraphRagInputs(cases[3].sourceCode);
const changedSourceHash = hashGraphRagInputs(`${cases[3].sourceCode}\n// cache-invalidation-probe`);
assert.notEqual(cachedSourceHash, changedSourceHash, 'GraphRAG cache hash changes with source content');

const firstCachedResult = buildContractSecurityGraph(cases[3].sourceCode);
const secondCachedResult = buildContractSecurityGraph(cases[3].sourceCode);
assert.deepEqual(secondCachedResult, firstCachedResult, 'GraphRAG snapshots preserve deterministic results');

console.log('GraphRAG evaluation');
console.log(`True Positives: ${truePositives}`);
console.log(`False Positives: ${falsePositives}`);
console.log(`False Negatives: ${falseNegatives}`);
console.log(`Precision: ${precision.toFixed(4)}`);
console.log(`Recall: ${recall.toFixed(4)}`);
console.log(`F1-Score: ${f1.toFixed(4)}`);
