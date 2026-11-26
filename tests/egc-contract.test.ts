import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomUUID } from 'node:crypto';
import { Keypair } from '@solana/web3.js';
import manifest from '../src/mcp/manifest.json' with { type: 'json' };
import {
  executeEgcContractCommand,
  redactEgcResult,
} from '../src/application/egcCommandService.ts';
import { EGC_V1_COMMANDS } from '../src/contracts/v1/index.ts';
import { MCP_TOOLS } from '../src/mcp/server.ts';
import { ANCHOR_DEVSECOPS_BPMN_TASKS, generateOmgBpmnXml } from '../src/services/bpmnWorkflowService.ts';

async function withHttpServer<T>(
  app: import('express').Express,
  run: (baseUrl: string) => Promise<T>,
): Promise<T> {
  const server = createServer(app);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  assert(address && typeof address !== 'string');

  try {
    return await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve());
    });
  }
}

async function main() {
  assert.deepEqual(
    manifest.tools.map(tool => tool.name),
    MCP_TOOLS.map(tool => tool.name),
    'Static manifest matches runtime MCP catalog',
  );
  assert.deepEqual(
    manifest.tools.map(tool => tool.inputSchema),
    MCP_TOOLS.map(tool => tool.inputSchema),
    'Static manifest input schemas match runtime MCP schemas',
  );
  assert.equal(MCP_TOOLS.length, Object.keys(EGC_V1_COMMANDS).length);
  const bpmnXml = generateOmgBpmnXml();
  assert.ok(bpmnXml.includes('isExecutable="false"'));
  assert.ok(bpmnXml.includes('Parâmetros válidos?'));
  assert.ok(bpmnXml.includes('Pull Request criado?'));
  assert.ok(!bpmnXml.includes('10,000'));
  assert.ok(ANCHOR_DEVSECOPS_BPMN_TASKS.every(task => task.status === 'NOT_EXECUTED'));
  assert.deepEqual(redactEgcResult({ message: 'prefix-secret-suffix' }, { token: 'secret' }), {
    message: 'prefix-[REDACTED]-suffix',
  });

  const correlationId = randomUUID();
  const invalid = await executeEgcContractCommand(
    'audit_rust_ast',
    { sourceCode: 42, unexpected: true },
    correlationId,
  );
  assert.equal(invalid.success, false);
  if (!invalid.success) {
    assert.equal(invalid.error.code, 'INVALID_INPUT');
    assert.equal(invalid.correlationId, correlationId);
    assert.ok(invalid.timestamp);
    assert.ok(invalid.error.issues?.length);
  }

  const unknown = await executeEgcContractCommand('not_a_command', {});
  assert.equal(unknown.success, false);
  if (!unknown.success) assert.equal(unknown.error.code, 'UNKNOWN_COMMAND');

  const valid = await executeEgcContractCommand('generate_anchor_contract', {});
  assert.equal(valid.success, true);
  if (valid.success) {
    const result = EGC_V1_COMMANDS.generate_anchor_contract.outputSchema.parse(valid.result);
    assert.equal(typeof result.rustSourceCode, 'string');
    assert.equal(result.spaceAnalysis.totalBytes, 49);
  }

  const invalidPda = await executeEgcContractCommand('derive_pda_spec', {
    authorityPubkey: 'not-a-public-key',
  });
  assert.equal(invalidPda.success, false);
  if (!invalidPda.success) assert.equal(invalidPda.error.code, 'INVALID_INPUT');

  const publicKey = Keypair.generate().publicKey.toBase58();
  const batch = await executeEgcContractCommand('record_batch_audit_receipts', {
    auditorPubkey: publicKey,
    items: [{
      targetProgram: publicKey,
      auditHash: '01',
      riskLevel: 1,
      findingsCount: 1,
      securityScore: 90,
    }],
  });
  assert.equal(batch.success, true);
  if (batch.success) {
    const result = EGC_V1_COMMANDS.record_batch_audit_receipts.outputSchema.parse(batch.result);
    assert.equal(result.success, false);
    assert.equal(result.submitted, false);
    assert.equal(result.submissionStatus, 'NOT_SUBMITTED');
  }

  process.env.ADMIN_API_KEY = randomUUID();
  process.env.EGC_DISABLE_LISTEN = '1';
  const [{ default: apiApp }, { default: serverApp }] = await Promise.all([
    import('../api/index.ts'),
    import('../server.ts'),
  ]);
  const adminHeader = { authorization: `Bearer ${process.env.ADMIN_API_KEY}` };

  for (const app of [apiApp, serverApp]) {
    await withHttpServer(app, async baseUrl => {
      const protectedPaths = [
        ['GET', '/api/mcp/manifest'],
        ['GET', '/api/v1/contract'],
        ['POST', '/api/mcp/execute'],
        ['POST', '/api/v1/execute'],
      ] as const;

      for (const [method, path] of protectedPaths) {
        const response = await fetch(`${baseUrl}${path}`, {
          method,
          headers: { 'content-type': 'application/json' },
          ...(method === 'POST' ? { body: JSON.stringify({ tool: 'egc_contract_catalog' }) } : {}),
        });
        assert.equal(response.status, 403, `${method} ${path} rejects unauthenticated callers`);
      }

      const response = await fetch(`${baseUrl}/api/v1/execute`, {
        method: 'POST',
        headers: { ...adminHeader, 'content-type': 'application/json' },
        body: JSON.stringify({
          command: 'egc_contract_catalog',
          input: {},
          correlationId,
        }),
      });
      assert.equal(response.status, 200);
      const envelope = await response.json() as { success: boolean; correlationId: string };
      assert.equal(envelope.success, true);
      assert.equal(envelope.correlationId, correlationId);

      const invalidResponse = await fetch(`${baseUrl}/api/v1/execute`, {
        method: 'POST',
        headers: { ...adminHeader, 'content-type': 'application/json' },
        body: JSON.stringify({
          command: 'audit_rust_ast',
          input: { sourceCode: 42 },
          correlationId,
        }),
      });
      assert.equal(invalidResponse.status, 400);
      const invalidEnvelope = await invalidResponse.json() as {
        success: boolean;
        correlationId: string;
        error: { code: string };
      };
      assert.equal(invalidEnvelope.success, false);
      assert.equal(invalidEnvelope.error.code, 'INVALID_INPUT');
      assert.equal(invalidEnvelope.correlationId, correlationId);
    });
  }

  console.log('EGC v1 contract tests passed.');
}

main().catch(error => {
  console.error('EGC v1 contract tests failed:', error);
  process.exitCode = 1;
});
