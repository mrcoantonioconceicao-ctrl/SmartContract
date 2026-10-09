/**
 * Automated Verification & Self-Test Script for Solana Anchor MCP / EGC Integration
 * Plug-and-play test runner for Felipe Marzock and team members.
 * Run via: npm run test:mcp
 */

import { executeMcpToolDirect, MCP_TOOLS } from './server.ts';
import manifest from './manifest.json' with { type: 'json' };

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const CYAN = '\x1b[36m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

async function runTests() {
  console.log(`${BOLD}${CYAN}================================================================${RESET}`);
  console.log(`${BOLD}${CYAN} 🛡️  SOLANA ANCHOR DEVSECOPS - MCP & EGC INTEGRATION TEST SUITE ${RESET}`);
  console.log(`${BOLD}${CYAN}================================================================${RESET}\n`);

  let totalTests = 0;
  let passedTests = 0;

  function assert(condition: boolean, message: string) {
    totalTests++;
    if (condition) {
      passedTests++;
      console.log(`  ${GREEN}✔ [PASS]${RESET} ${message}`);
    } else {
      console.error(`  ${RED}✖ [FAIL]${RESET} ${message}`);
      throw new Error(`Assertion failed: ${message}`);
    }
  }

  // -------------------------------------------------------------
  // Test 1: MCP Manifest & Tool Registrations
  // -------------------------------------------------------------
  console.log(`${BOLD}[1/4] Verifying MCP Manifest & Tool Schema Definitions...${RESET}`);
  assert(manifest.name === 'solana-anchor-devsecops-mcp', 'Manifest has valid server name');
  assert(Array.isArray(manifest.tools) && manifest.tools.length >= 3, 'Manifest registers at least 3 tools');
  
  const toolNames = MCP_TOOLS.map(t => t.name);
  assert(toolNames.includes('generate_anchor_contract'), 'generate_anchor_contract tool registered');
  assert(toolNames.includes('audit_rust_ast'), 'audit_rust_ast tool registered');
  assert(toolNames.includes('create_github_pr'), 'create_github_pr tool registered');
  console.log('');

  // -------------------------------------------------------------
  // Test 2: generate_anchor_contract
  // -------------------------------------------------------------
  console.log(`${BOLD}[2/4] Testing generate_anchor_contract tool execution...${RESET}`);
  const genResult: any = await executeMcpToolDirect('generate_anchor_contract', {
    programName: 'solana_sandbox_counter',
    accountName: 'UserCounter',
    pdaPrefix: 'counter',
    hasCheckedMath: true,
    hasSignerCheck: true,
  });

  assert(typeof genResult.rustSourceCode === 'string', 'Generated Rust source code is string');
  assert(genResult.rustSourceCode.includes('declare_id!'), 'Contains declare_id! macro');
  assert(genResult.rustSourceCode.includes('checked_add'), 'Contains checked arithmetic overflow protection');
  assert(genResult.rustSourceCode.includes('has_one = authority'), 'Enforces authority ownership guard');
  assert(genResult.spaceAnalysis.totalBytes === 49, 'Space calculation equals exact 49 bytes');
  assert(genResult.securityGuards.manualMergeOnly === true, 'Enforces manual-only merge policy');
  console.log('');

  // -------------------------------------------------------------
  // Test 3: audit_rust_ast
  // -------------------------------------------------------------
  console.log(`${BOLD}[3/4] Testing audit_rust_ast static security analysis...${RESET}`);
  const auditReport: any = await executeMcpToolDirect('audit_rust_ast', {
    sourceCode: genResult.rustSourceCode,
  });

  assert(typeof auditReport.score === 'number', 'Audit returns numeric security score');
  assert(auditReport.score >= 90, `Secure contract achieves high score (${auditReport.score}/100)`);
  assert(auditReport.status === 'SECURE', 'Secure contract is marked SECURE');
  assert(auditReport.accountSpaceAnalysis.isExact === true, 'Memory layout is exact');

  // Negative test: unconstrained vulnerable contract
  const vulnerableCode = `
    #[program]
    pub mod vulnerable {
        pub fn insecure_add(ctx: Context<Insecure>, amount: u64) -> Result<()> {
            ctx.accounts.counter.count += amount; // Raw arithmetic overflow!
            Ok(())
        }
    }
  `;
  const vulnReport: any = await executeMcpToolDirect('audit_rust_ast', {
    sourceCode: vulnerableCode,
  });
  assert(vulnReport.findings.length > 0, 'Vulnerable code triggers AST findings');
  console.log('');

  // -------------------------------------------------------------
  // Test 4: create_github_pr (Mandatory PAT validation & Manual Merge)
  // -------------------------------------------------------------
  console.log(`${BOLD}[4/4] Testing create_github_pr security validations...${RESET}`);
  
  // Test 4a: Missing token must be rejected
  let missingTokenBlocked = false;
  try {
    await executeMcpToolDirect('create_github_pr', {
      token: '',
      owner: 'mrcoantonioconceicao-ctrl',
      repoName: 'SlipPay2',
    });
  } catch (err: any) {
    if (err.message.includes('obrigatório')) {
      missingTokenBlocked = true;
    }
  }
  assert(missingTokenBlocked, 'Empty or missing GitHub token is strictly blocked');

  // Test 4b: Invalid token format must be rejected
  let invalidFormatBlocked = false;
  try {
    await executeMcpToolDirect('create_github_pr', {
      token: 'not_a_real_token',
      owner: 'mrcoantonioconceicao-ctrl',
      repoName: 'SlipPay2',
    });
  } catch (err: any) {
    if (err.message.includes('ghp_') || err.message.includes('github_pat_')) {
      invalidFormatBlocked = true;
    }
  }
  assert(invalidFormatBlocked, 'Invalid token prefix (without ghp_ or github_pat_) is strictly blocked');

  // Test 4c: Missing owner/repo must be rejected
  let missingOwnerBlocked = false;
  try {
    await executeMcpToolDirect('create_github_pr', {
      token: 'ghp_fakeTokenForValidationTesting1234567890',
      owner: '',
      repoName: 'SlipPay2',
    });
  } catch (err: any) {
    if (err.message.includes('obrigatório')) {
      missingOwnerBlocked = true;
    }
  }
  assert(missingOwnerBlocked, 'Missing repository owner is strictly blocked');
  console.log('');

  // -------------------------------------------------------------
  // Test 5: Real Repository AST Scanner & GitHub Issues Engine (Zero Mocks)
  // -------------------------------------------------------------
  console.log(`${BOLD}[5/5] Testing EGC Real Repository AST Scanner & GitHub Issues Engine...${RESET}`);

  // Test 5a: Deep real scan executes on project files
  const scanResult: any = await executeMcpToolDirect('scan_repository_ast', {});
  assert(scanResult && scanResult.scannedFilesCount > 0, 'Real scanner inspects physical project files');
  assert(scanResult.solanaGuarantees.deterministicPdas === true, 'Solana Guarantee: Deterministic PDAs verified');
  assert(scanResult.solanaGuarantees.rentExemptMemory49B === true, 'Solana Guarantee: Rent-Exempt 49B verified');
  assert(scanResult.solanaGuarantees.checkedArithmetic === true, 'Solana Guarantee: Checked arithmetic verified');
  assert(scanResult.solanaGuarantees.signerAuthorization === true, 'Solana Guarantee: Signer & has_one verified');

  // Test 5b: Issue creator validates token
  let missingTokenIssueBlocked = false;
  try {
    await executeMcpToolDirect('create_github_issues', {
      token: '',
      owner: 'mrcoantonioconceicao-ctrl',
      repoName: 'SlipPay2',
    });
  } catch (err: any) {
    if (err.message.includes('obrigatório') || err.message.includes('obrigatorio')) {
      missingTokenIssueBlocked = true;
    }
  }
  assert(missingTokenIssueBlocked, 'create_github_issues blocks empty token');
  console.log('');

  // -------------------------------------------------------------
  // Test 6: Contextual Architecture Engine (GraphRAG, DDD, SOA & AST Context)
  // -------------------------------------------------------------
  console.log(`${BOLD}[6/6] Testing Contextual Architecture Engine (GraphRAG, DDD, SOA & AST)...${RESET}`);
  const archResult: any = await executeMcpToolDirect('analyze_contextual_architecture', {});
  assert(archResult && archResult.filesScanned.length > 0, 'Contextual engine inspects repository file tree');
  assert(archResult.graphRag && archResult.graphRag.nodes.length >= 5, 'GraphRAG semantic graph maps cross-instruction nodes');
  assert(archResult.graphRag.attackPaths.length >= 3, 'GraphRAG maps attack paths (Impersonation, Overflow, Rent)');
  assert(archResult.dddModel.boundedContext === 'SolanaAnchorCounterDomain', 'DDD Bounded Context mapped correctly');
  assert(archResult.dddModel.aggregateRoot === 'UserCounter', 'DDD Aggregate Root identified as UserCounter');
  assert(archResult.dddModel.invariants.length >= 4, 'DDD Invariants verified for rent, PDA, math, and access');
  assert(archResult.soaServices.length >= 5, 'SOA Microservices catalog linked to audit pipeline');
  assert(archResult.ruleC44Compliant === true, 'Regra C44: Non-destructive compliance verified');
  console.log('');

  // -------------------------------------------------------------
  // Test 7: Static Solana Anchor Lint (anchor-lint) Engine
  // -------------------------------------------------------------
  console.log(`${BOLD}[7/7] Testing Solana Anchor Lint (anchor-lint) Engine...${RESET}`);
  const lintResult: any = await executeMcpToolDirect('run_anchor_lint', {});
  assert(lintResult && lintResult.filesInspected.length > 0, 'anchor-lint inspects physical Rust files');
  assert(lintResult.passed === true, 'anchor-lint passes on secure contracts with zero errors');
  assert(lintResult.errorCount === 0, 'Zero anti-pattern errors on production codebase');

  // Test anti-pattern detection on intentionally vulnerable code
  const vulnerableAnchorCode = `
    #[derive(Accounts)]
    pub struct Insecure<'info> {
      pub authority: AccountInfo<'info>,
      #[account(mut)]
      pub counter: Account<'info, UserCounter>,
    }
  `;
  const antiPatternTest: any = await executeMcpToolDirect('run_anchor_lint', {
    files: [{ path: 'programs/test/src/vulnerable.rs', content: vulnerableAnchorCode }]
  });
  assert(antiPatternTest.passed === false, 'anchor-lint detects anti-patterns in vulnerable code');
  assert(antiPatternTest.issues.length >= 2, 'anchor-lint flags unvalidated AccountInfo authority and missing has_one');
  console.log('');

  // -------------------------------------------------------------
  // Summary
  // -------------------------------------------------------------
  console.log(`${BOLD}${GREEN}================================================================${RESET}`);
  console.log(`${BOLD}${GREEN} ✔ ALL TESTS PASSED SUCCESSFULLY (${passedTests}/${totalTests})${RESET}`);
  console.log(`${BOLD}${GREEN} MCP Server and EGC Execution Adapter are 100% Plug-and-Play!${RESET}`);
  console.log(`${BOLD}${GREEN}================================================================${RESET}`);
}

runTests().catch((error) => {
  console.error(`\n${RED}Test suite failed:${RESET}`, error);
  process.exit(1);
});
