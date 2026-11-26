const RUST_RESERVED_IDENTIFIERS = [
  'as',
  'break',
  'const',
  'continue',
  'crate',
  'else',
  'enum',
  'extern',
  'false',
  'fn',
  'for',
  'if',
  'impl',
  'in',
  'let',
  'loop',
  'match',
  'mod',
  'move',
  'mut',
  'pub',
  'ref',
  'return',
  'Self',
  'self',
  'static',
  'struct',
  'super',
  'trait',
  'true',
  'type',
  'unsafe',
  'use',
  'where',
  'while',
  'async',
  'await',
  'dyn',
  'abstract',
  'become',
  'box',
  'do',
  'final',
  'macro',
  'override',
  'priv',
  'typeof',
  'unsized',
  'virtual',
  'yield',
  'try',
  'gen',
] as const;

const reservedIdentifierSet = new Set<string>(RUST_RESERVED_IDENTIFIERS);
const moduleKeywords = RUST_RESERVED_IDENTIFIERS.filter(
  keyword => keyword === keyword.toLowerCase(),
);
const accountKeywords = new Set(
  RUST_RESERVED_IDENTIFIERS.flatMap(keyword => [
    keyword,
    `${keyword[0].toUpperCase()}${keyword.slice(1)}`,
  ]),
);

export const RUST_MODULE_NAME_PATTERN = new RegExp(
  `^(?!(?:${moduleKeywords.join('|')})$)[a-z][a-z0-9_]{0,63}$`,
);

export const RUST_ACCOUNT_NAME_PATTERN = new RegExp(
  `^(?!(?:${[...accountKeywords].join('|')})$)[A-Z][A-Za-z0-9]{0,63}$`,
);

export function isRustIdentifier(value: string): boolean {
  return value !== '_' &&
    /^[A-Za-z_][A-Za-z0-9_]*$/.test(value) &&
    !reservedIdentifierSet.has(value);
}

export function isRustModuleName(value: string): boolean {
  return RUST_MODULE_NAME_PATTERN.test(value);
}

export function isRustAccountTypeName(value: string): boolean {
  return RUST_ACCOUNT_NAME_PATTERN.test(value) && isRustIdentifier(value.toLowerCase());
}
