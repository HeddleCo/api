import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { normalizePasskeyLabel, passkeyDisplayLabel, DEFAULT_PASSKEY_LABEL } from '../packages/typescript/dist/v1alpha2/passkey-label.js';

test('passkey labels trim, count UTF-8 bytes, reject controls, and use the default', () => {
  assert.equal(normalizePasskeyLabel('  Work laptop  '), 'Work laptop');
  assert.equal(normalizePasskeyLabel('   '), '');
  assert.equal(passkeyDisplayLabel(''), DEFAULT_PASSKEY_LABEL);
  assert.equal(passkeyDisplayLabel('Work laptop'), 'Work laptop');
  assert.equal(normalizePasskeyLabel('é'.repeat(128)), 'é'.repeat(128));
  for (const label of ['x'.repeat(257), 'é'.repeat(129)]) {
    assert.throws(() => normalizePasskeyLabel(label), /256 UTF-8 bytes/);
  }
  for (const label of ['a\nb', '\tname', 'name\x7f', 'name\x85']) {
    assert.throws(() => normalizePasskeyLabel(label), /control character/);
  }
});

const vectors = JSON.parse(readFileSync(new URL('./fixtures/passkey-label-unicode.json', import.meta.url), 'utf8'));
test('passkey label Unicode vectors match shared contract', () => {
  for (const { name, input, normalized } of vectors) {
    if (normalized === undefined) {
      assert.throws(() => normalizePasskeyLabel(input), undefined, name);
    } else {
      assert.equal(normalizePasskeyLabel(input), normalized, name);
    }
  }
});
