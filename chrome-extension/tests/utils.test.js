// Minimal test runner — no framework needed
if (typeof require !== 'undefined') {
  global.btoa = (s) => Buffer.from(s, 'binary').toString('base64');
}
const { buildEml, makeFingerprint, verdictToStyle } = require('../lib/utils.js');

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); console.log('  ✓', name); passed++; }
  catch (e) { console.error('  ✗', name + ':', e.message); failed++; }
}
function eq(a, b) {
  if (a !== b) throw new Error(`Expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
}
function ok(cond, msg) {
  if (!cond) throw new Error(msg || 'Expected truthy');
}

console.log('\nbuildEml');
test('includes From with name', () => {
  ok(buildEml({ fromName: 'Alice', fromAddress: 'a@b.com', subject: 'S', date: 'D', bodyText: '' })
    .includes('From: Alice <a@b.com>'));
});
test('uses address only when name is empty', () => {
  ok(buildEml({ fromName: '', fromAddress: 'x@y.com', subject: 'S', date: 'D', bodyText: '' })
    .includes('From: x@y.com'));
});
test('includes Subject header', () => {
  ok(buildEml({ fromName: '', fromAddress: 'a@b.com', subject: 'Urgent wire', date: 'D', bodyText: '' })
    .includes('Subject: Urgent wire'));
});
test('falls back to (no subject) when subject empty', () => {
  ok(buildEml({ fromName: '', fromAddress: 'a@b.com', subject: '', date: 'D', bodyText: '' })
    .includes('Subject: (no subject)'));
});
test('body text appears after blank line', () => {
  const eml = buildEml({ fromName: '', fromAddress: 'a@b.com', subject: 'S', date: 'D', bodyText: 'click here' });
  const parts = eml.split('\r\n\r\n');
  eq(parts[1], 'click here');
});
test('To header is analyst@mailtrace.local', () => {
  ok(buildEml({ fromName: '', fromAddress: 'a@b.com', subject: 'S', date: 'D', bodyText: '' })
    .includes('To: analyst@mailtrace.local'));
});

console.log('\nmakeFingerprint');
test('returns non-empty alphanumeric string', () => {
  const fp = makeFingerprint('a@b.com', 'Subject', '2026-01-01');
  ok(fp.length > 0, 'should not be empty');
  ok(/^[a-zA-Z0-9]+$/.test(fp), 'should be alphanumeric');
});
test('is deterministic for same inputs', () => {
  eq(makeFingerprint('a@b.com', 'S', 'D'), makeFingerprint('a@b.com', 'S', 'D'));
});
test('differs for different subjects', () => {
  ok(makeFingerprint('a@b.com', 'S1', 'D') !== makeFingerprint('a@b.com', 'S2', 'D'));
});
test('max 40 chars', () => {
  ok(makeFingerprint('very-long-address@very-long-domain.co.uk', 'A very long subject line for this email', '2026').length <= 40);
});

console.log('\nverdictToStyle');
test('phishing → red bg, DC2626, ✕ icon', () => {
  const s = verdictToStyle('phishing');
  eq(s.bg, '#FEF2F2'); eq(s.color, '#DC2626'); eq(s.icon, '✕');
});
test('PHISHING (uppercase) → red', () => {
  eq(verdictToStyle('PHISHING').color, '#DC2626');
});
test('malware → red', () => { eq(verdictToStyle('malware').color, '#DC2626'); });
test('bec → red', () => { eq(verdictToStyle('bec').color, '#DC2626'); });
test('suspicious → amber, D97706, ⚠ icon', () => {
  const s = verdictToStyle('suspicious');
  eq(s.bg, '#FEF3C7'); eq(s.color, '#D97706'); eq(s.icon, '⚠');
});
test('indeterminate → amber', () => { eq(verdictToStyle('indeterminate').color, '#D97706'); });
test('benign → green, 16A34A, ✓ icon', () => {
  const s = verdictToStyle('benign');
  eq(s.bg, '#F0FDF4'); eq(s.color, '#16A34A'); eq(s.icon, '✓');
});
test('clean → green', () => { eq(verdictToStyle('clean').color, '#16A34A'); });
test('likely_benign → green', () => { eq(verdictToStyle('likely_benign').color, '#16A34A'); });
test('unknown verdict → grey', () => { eq(verdictToStyle('').color, '#64748B'); });
test('label is uppercase of verdict', () => { eq(verdictToStyle('phishing').label, 'PHISHING'); });

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) process.exit(1);
