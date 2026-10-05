import assert from 'node:assert/strict';
import { test } from 'node:test';
import { create } from '@bufbuild/protobuf';
import * as api from '../packages/typescript/dist/v1alpha2/index.js';
import { CallFailureCode, ErrorReason } from '../packages/typescript/dist/common/index.js';

test('in-app DIGEST is rejected with typed InvalidArgument', () => {
  const rule = create(api.NotificationRuleSchema, {
    kind: 'mention', actorOrigin: 'human',
    channel: api.NotificationRule_Channel.IN_APP,
    delivery: api.NotificationRule_Delivery.DIGEST,
  });
  // Optional lookup makes this regression runnable against origin/main's
  // pre-helper exports: the missing rejection fails as an assertion.
  assert.throws(() => api.validateNotificationRule?.(rule), error =>
    error.code === CallFailureCode.INVALID_ARGUMENT &&
    error.reason === ErrorReason.FIELD_INVALID);
});

import { readFileSync } from 'node:fs';
import { toBinary, fromBinary } from '@bufbuild/protobuf';
const vectors = JSON.parse(readFileSync(new URL('./fixtures/notification-delivery.json', import.meta.url), 'utf8'));

test('Rust/TS parity for all modes, wildcards, origins and Spool scopes', () => {
  assert.equal(vectors.length, 150);
  for (const { kind, channel, delivery, violation } of vectors) {
    for (const actorOrigin of ['', 'any', 'human', 'agent']) {
      for (const spool of [undefined, create(api.SpoolRefSchema)]) {
        const rule = create(api.NotificationRuleSchema, { kind, channel, delivery, actorOrigin, spool });
        const request = create(api.SetNotificationPreferencesRequestSchema, {
          preferences: create(api.NotificationPreferencesSchema, { rules: [rule] }),
        });
        for (const validate of [() => api.validateNotificationRule(rule),
          () => api.validateNotificationPreferencesWrite(request)]) {
          if (violation) assert.throws(validate, error => error.violation === violation);
          else assert.doesNotThrow(validate);
        }
      }
    }
  }
});

test('locked email rejects unsubscribe and retains editable in-app', () => {
  for (const kind of ['account_security', 'security_surface', '', '*']) {
    const rule = create(api.NotificationRuleSchema, { kind, channel: 2, delivery: 3 });
    const request = create(api.UnsubscribeNotificationsRequestSchema, { rules: [rule] });
    assert.throws(() => api.validateUnsubscribeNotifications(request), error =>
      error.violation === 'LockedEmail' && error.code === CallFailureCode.FAILED_PRECONDITION &&
      error.reason === ErrorReason.POLICY_DENIED);
    rule.channel = 1;
    assert.doesNotThrow(() => api.validateUnsubscribeNotifications(request));
  }
  assert.throws(() => api.validateNotificationPreferencesWrite(create(api.SetNotificationPreferencesRequestSchema)),
    error => error.violation === 'InvalidRule');
  assert.throws(() => api.validateUnsubscribeNotifications(create(api.UnsubscribeNotificationsRequestSchema, {
    rules: [create(api.NotificationRuleSchema, { kind: 'mention', channel: 2, delivery: 1 })],
  })), error => error.violation === 'UnsubscribeDelivery');
});

test('additive descriptor and wire fields remain on the same preferences read', () => {
  for (const [schema, name, number] of [
    [api.NotificationPreferencesSchema, 'effective_delivery', 6],
    [api.NotificationPreferencesSchema, 'next_digest_at', 7],
    [api.NotificationDigestOverrideSchema, 'next_digest_at', 3],
    ...['kind', 'spool', 'actor_origin', 'channel', 'delivery', 'source', 'locked', 'source_spool'].map((name, i) =>
      [api.EffectiveDeliverySchema, name, i + 1]),
  ]) assert.equal(schema.fields.find(field => field.name === name)?.number, number);
  assert.deepEqual([api.EffectiveDelivery_Source.UNSPECIFIED, api.EffectiveDelivery_Source.RULE,
    api.EffectiveDelivery_Source.DEFAULT, api.EffectiveDelivery_Source.INHERITED,
    api.EffectiveDelivery_Source.ACCOUNT], [0, 1, 2, 3, 4]);
  const preferences = create(api.NotificationPreferencesSchema, {
    effectiveDelivery: [create(api.EffectiveDeliverySchema, {
      kind: 'account_security', channel: 2, delivery: 1, source: 2, locked: true,
    }), create(api.EffectiveDeliverySchema, {
      kind: 'mention', actorOrigin: 'agent', channel: 2, delivery: 1, source: 1,
      spool: create(api.SpoolRefSchema),
    })],
    nextDigestAt: { seconds: 1800000000n, nanos: 123 },
    digestOverrides: [create(api.NotificationDigestOverrideSchema, {
      spool: create(api.SpoolRefSchema), digestInterval: { seconds: 0n, nanos: 0 },
    })],
  });
  const event = create(api.NotificationEventSchema, { payload: { case: 'preferences', value: preferences } });
  assert.deepEqual(fromBinary(api.NotificationEventSchema, toBinary(api.NotificationEventSchema, event)), event);
  assert.doesNotThrow(() => api.validateNotificationPreferencesWrite(
    create(api.SetNotificationPreferencesRequestSchema, { preferences })));
  const legacy = fromBinary(api.NotificationPreferencesSchema, new Uint8Array());
  assert.deepEqual(legacy.effectiveDelivery, []);
  assert.equal(legacy.nextDigestAt, undefined);
});

test('effective projection count and whole-message byte bounds are enforced', () => {
  const preferences = create(api.NotificationPreferencesSchema, {
    effectiveDelivery: Array.from({ length: api.MAX_EFFECTIVE_DELIVERIES }, () => create(api.EffectiveDeliverySchema)),
  });
  assert.doesNotThrow(() => api.validateNotificationPreferencesBound(preferences));
  preferences.effectiveDelivery.push(create(api.EffectiveDeliverySchema));
  assert.throws(() => api.validateNotificationPreferencesBound(preferences), error => error.violation === 'ProjectionTooLarge');
  preferences.effectiveDelivery = [];
  preferences.timezone = 'x'.repeat(api.MAX_NOTIFICATION_PREFERENCES_BYTES - 4);
  assert.equal(toBinary(api.NotificationPreferencesSchema, preferences).length, api.MAX_NOTIFICATION_PREFERENCES_BYTES);
  assert.doesNotThrow(() => api.validateNotificationPreferencesBound(preferences));
  preferences.timezone += 'x';
  assert.throws(() => api.validateNotificationPreferencesBound(preferences), error =>
    error.code === CallFailureCode.RESOURCE_EXHAUSTED && error.reason === ErrorReason.QUOTA_EXCEEDED);
});


test('locked email takes precedence over wildcard DIGEST with typed PolicyDenied', () => {
  for (const kind of ['', '*', 'account_security', 'security_surface']) {
    const rule = create(api.NotificationRuleSchema, { kind, channel: 0, delivery: 2 });
    assert.throws(() => api.validateNotificationRule(rule), error =>
      error.violation === 'LockedEmail' && error.code === CallFailureCode.FAILED_PRECONDITION &&
      error.reason === ErrorReason.POLICY_DENIED);
  }
  for (const [kind, channel] of [['mention', 0], ['account_security', 1], ['security_surface', 1]]) {
    assert.throws(() => api.validateNotificationRule(create(api.NotificationRuleSchema, {
      kind, channel, delivery: 2,
    })), error => error.violation === 'DigestRequiresEmail' &&
      error.code === CallFailureCode.INVALID_ARGUMENT && error.reason === ErrorReason.FIELD_INVALID);
  }
});

const cadenceVectors = JSON.parse(readFileSync(new URL('./fixtures/notification-cadence.json', import.meta.url), 'utf8'));
for (const { name, scope, interval, violation } of cadenceVectors) {
  test(`settings cadence: ${name}`, () => {
    const duration = interval ? { seconds: BigInt(interval.seconds), nanos: interval.nanos } : undefined;
    const preferences = create(api.NotificationPreferencesSchema, scope === 'account' ? {
      digestInterval: duration,
    } : {
      digestOverrides: [create(api.NotificationDigestOverrideSchema, {
        spool: create(api.SpoolRefSchema, { id: '00000000-0000-4000-8000-000000000001' }),
        digestInterval: duration,
      })],
    });
    const validate = () => api.validateNotificationPreferencesWrite(
      create(api.SetNotificationPreferencesRequestSchema, { preferences }));
    if (violation) assert.throws(validate, error => error.violation === violation &&
      error.code === CallFailureCode.INVALID_ARGUMENT && error.reason === ErrorReason.FIELD_INVALID);
    else assert.doesNotThrow(validate);
  });
}
