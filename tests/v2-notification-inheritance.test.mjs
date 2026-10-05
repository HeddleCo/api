import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';

const vectors = JSON.parse(readFileSync(new URL('./fixtures/notification-inheritance.json', import.meta.url), 'utf8'));
const ref = id => id === null || id === undefined ? undefined : { id };
const result = cell => ({ delivery: cell.delivery, source: cell.source, sourceSpool: cell.sourceSpool?.id ?? null, locked: cell.locked });

test('shared inheritance selection, provenance, removal and privacy vectors', () => {
  for (const v of vectors) {
    const rules = v.rules.map(r => create(api.NotificationRuleSchema, { ...r, spool: ref(r.spool) }));
    const ancestors = v.ancestors.map(a => ({ ...a, spool: ref(a.spool) }));
    const cell = create(api.EffectiveDeliverySchema, { ...v.cell, spool: ref(v.cell.spool) });
    const resolve = r => api.resolveNotificationDelivery(r, cell, ancestors, 128, v.defaultDelivery, v.digestEnabled);
    if (v.name === 'system root rule invalid') {
      assert.throws(() => api.validateNotificationPreferencesWriteForSystemRoot(
        create(api.SetNotificationPreferencesRequestSchema, { preferences: { rules } }), ancestors.at(-1).spool,
      ), e => e.violation === 'InvalidRule');
    }
    if (v.violation) {
      assert.throws(() => resolve(rules), e => e.violation === v.violation, v.name);
      if (v.violation === 'InvalidRule' && v.name.includes('unspecified')) {
        assert.throws(() => api.validateNotificationPreferencesWrite(create(api.SetNotificationPreferencesRequestSchema, {
          preferences: { rules },
        })), e => e.violation === 'InvalidRule', v.name);
      }
      continue;
    }
    const resolved = resolve(rules);
    assert.deepEqual(result(resolved), v.expected, v.name);
    assert.equal(resolved.spool?.id, cell.spool?.id, v.name);
    assert.doesNotThrow(() => api.validateEffectiveDeliverySource(resolved, ancestors, 128), v.name);
    assert.deepEqual(fromBinary(api.EffectiveDeliverySchema, toBinary(api.EffectiveDeliverySchema, resolved)), resolved);
    if ('spoofSourceSpool' in v) {
      const spoofed = create(api.EffectiveDeliverySchema, { ...resolved, sourceSpool: ref(v.spoofSourceSpool) });
      assert.throws(() => api.validateEffectiveDeliverySource(spoofed, ancestors, 128), e => e.violation === 'InvalidSource', v.name);
    }
    if (v.removeSpool) {
      assert.deepEqual(result(resolve(rules.filter(r => r.spool?.id !== v.removeSpool))), v.after, v.name);
    }
  }
});

test('64/128 ancestry limits are inclusive and overflow never falls back', () => {
  for (const limit of [64, 128]) {
    const ancestors = Array.from({ length: limit }, (_, i) => ({ spool: { id: `00000000-0000-4000-8000-${String(i).padStart(12, '0')}` }, readable: true, systemRoot: false }));
    const cell = create(api.EffectiveDeliverySchema, { kind: 'mention', actorOrigin: 'human', channel: 2, spool: ancestors[0].spool });
    const rule = create(api.NotificationRuleSchema, { kind: 'mention', channel: 2, delivery: 3, spool: ancestors.at(-1).spool });
    const resolved = api.resolveNotificationDelivery([rule], cell, ancestors, limit, 1, true);
    assert.equal(resolved.delivery, 3);
    assert.equal(resolved.sourceSpool.id, ancestors.at(-1).spool.id);
    ancestors.push({ spool: { id: '00000000-0000-4000-8000-000000000999' }, readable: true, systemRoot: false });
    assert.throws(() => api.resolveNotificationDelivery([], cell, ancestors, limit, 1, true), e => e.violation === 'InvalidAncestry');
  }
});
