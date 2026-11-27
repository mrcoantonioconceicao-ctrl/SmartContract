import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const GRAPHRAG_CACHE_VERSION = 2;

interface GraphRagCacheSnapshot {
  cacheVersion: number;
  sourceHash: string;
  graphHash: string;
  result: unknown;
}

function isNodeRuntime(): boolean {
  return typeof process !== 'undefined'
    && typeof process.cwd === 'function'
    && typeof window === 'undefined';
}

export function hashGraphRagInputs(
  sourceCode: string,
  extraFiles?: Array<{ path: string; content: string }>,
): string {
  const normalizedFiles = (extraFiles ?? [])
    .map(file => ({
      path: file.path.replace(/\\/g, '/'),
      content: file.content,
    }))
    .sort((left, right) => left.path.localeCompare(right.path))
  const serialized = JSON.stringify({ sourceCode, extraFiles: normalizedFiles });
  if (!isNodeRuntime()) {
    let hash = 2166136261;
    for (let index = 0; index < serialized.length; index += 1) {
      hash ^= serialized.charCodeAt(index);
      hash = Math.imul(hash, 16777619);
    }
    return `browser-${(hash >>> 0).toString(16).padStart(8, '0')}`;
  }
  const hash = createHash('sha256');
  hash.update(serialized);
  return hash.digest('hex');
}

export function getGraphRagCacheDirectory(): string | null {
  if (!isNodeRuntime()) return null;
  const cwd = process.cwd();
  return join(cwd, '.egc', 'cache', 'graphrag');
}

export function readGraphRagSnapshot(
  sourceHash: string,
): GraphRagCacheSnapshot | null {
  const cacheDirectory = getGraphRagCacheDirectory();
  if (!cacheDirectory) return null;
  const snapshotPath = join(cacheDirectory, `${sourceHash}.json`);
  if (!existsSync(snapshotPath)) return null;
  try {
    const snapshot = JSON.parse(readFileSync(snapshotPath, 'utf8')) as GraphRagCacheSnapshot;
    if (
      snapshot.cacheVersion !== GRAPHRAG_CACHE_VERSION
      || snapshot.sourceHash !== sourceHash
    ) return null;
    return snapshot;
  } catch {
    return null;
  }
}

export function writeGraphRagSnapshot(
  sourceHash: string,
  result: unknown,
): GraphRagCacheSnapshot | null {
  const cacheDirectory = getGraphRagCacheDirectory();
  if (!cacheDirectory) return null;
  try {
    mkdirSync(cacheDirectory, { recursive: true });
    const serialized = JSON.stringify(result);
    const snapshot: GraphRagCacheSnapshot = {
      cacheVersion: GRAPHRAG_CACHE_VERSION,
      sourceHash,
      graphHash: createHash('sha256').update(serialized).digest('hex'),
      result,
    };
    writeFileSync(
      join(cacheDirectory, `${sourceHash}.json`),
      `${JSON.stringify(snapshot, null, 2)}\n`,
      'utf8',
    );
    return snapshot;
  } catch {
    return null;
  }
}
