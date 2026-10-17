// Unit tests for pure auth logic (no database needed).
// Usage: npm run smoke
import {
  normalizeEmail, assertEmail, assertDisplayName, assertPassword, assertTerms, bodyObject,
  ValidationError,
} from '../api/_lib/validate.js';
import { hashPassword, verifyPassword } from '../api/_lib/passwords.js';
import { newToken, hashToken, hashEquals } from '../api/_lib/tokens.js';

let passed = 0;
let failed = 0;
function ok(name: string, cond: boolean): void {
  if (cond) { passed++; }
  else { failed++; console.error('FAIL:', name); }
}
function throwsValidation(name: string, fn: () => void): void {
  try { fn(); ok(name, false); }
  catch (e) { ok(name, e instanceof ValidationError); }
}

async function main(): Promise<void> {
  // email
  ok('normalize trims+lowercases', normalizeEmail('  Foo@Bar.COM ') === 'foo@bar.com');
  ok('accepts valid email', assertEmail('a@b.co') === 'a@b.co');
  throwsValidation('rejects missing @', () => assertEmail('not-an-email'));
  throwsValidation('rejects empty', () => assertEmail('  '));
  throwsValidation('rejects non-string', () => assertEmail(42));

  // display name
  ok('trims name', assertDisplayName('  Ada  Lovelace ') === 'Ada Lovelace');
  throwsValidation('rejects empty name', () => assertDisplayName('   '));
  throwsValidation('rejects long name', () => assertDisplayName('x'.repeat(61)));

  // password
  ok('accepts 10-char password', assertPassword('correct horse') === 'correct horse');
  throwsValidation('rejects short password', () => assertPassword('short1'));
  throwsValidation('rejects common password', () => assertPassword('password1234'));
  throwsValidation('rejects >128 chars', () => assertPassword('x'.repeat(129)));

  // terms + body
  throwsValidation('rejects missing terms', () => assertTerms(false));
  ok('accepts terms', (assertTerms(true), true));
  throwsValidation('rejects array body', () => bodyObject([]));
  ok('accepts object body', typeof bodyObject({ a: 1 }) === 'object');

  // scrypt roundtrip
  const hash = await hashPassword('correct horse battery staple');
  ok('hash format', hash.startsWith('scrypt$16384$8$1$'));
  ok('verifies correct password', await verifyPassword('correct horse battery staple', hash));
  ok('rejects wrong password', !(await verifyPassword('wrong password', hash)));
  ok('rejects malformed hash', !(await verifyPassword('x', 'not-a-hash')));
  ok('rejects empty hash', !(await verifyPassword('x', '')));
  const hash2 = await hashPassword('correct horse battery staple');
  ok('salts differ', hash !== hash2);

  // tokens
  const t1 = newToken();
  const t2 = newToken();
  ok('tokens unique', t1 !== t2 && t1.length >= 40);
  ok('hash deterministic', hashToken(t1) === hashToken(t1));
  ok('hash differs per token', hashToken(t1) !== hashToken(t2));
  ok('hash looks like sha256 hex', /^[0-9a-f]{64}$/.test(hashToken(t1)));
  ok('hashEquals true', hashEquals(hashToken(t1), hashToken(t1)));
  ok('hashEquals false', !hashEquals(hashToken(t1), hashToken(t2)));

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
