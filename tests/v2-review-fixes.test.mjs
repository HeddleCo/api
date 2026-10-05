import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { create } from '@bufbuild/protobuf';
import { InvitationRecordSchema, InvitationState } from '../packages/typescript/dist/v1alpha2/administration_pb.js';
import { ObserveNotificationsRequestSchema, SpoolEventSchema } from '../packages/typescript/dist/v1alpha2/views_pb.js';
import { NotificationPreferencesSchema, NotificationRuleSchema, EffectiveDeliverySchema, SetNotificationPreferencesRequestSchema, NotificationRecordSchema, AttentionItemSchema } from '../packages/typescript/dist/v1alpha2/activity_pb.js';
import { validateInviterAuthority, planInvitationResponse, InvitationError, validateInvitationRecordProjection, validateSpoolInvitationProjection, validateNotificationInvitationProjection, validateAttentionInvitationProjection } from '../packages/typescript/dist/v1alpha2/invitation.js';
import { notificationProjectionScopes, replaceNotificationPreferences, resolveInvitationNotificationDelivery, resolveNotificationDelivery, validateEffectiveDeliverySource, validateNotificationPreferencesBound, NotificationValidationError } from '../packages/typescript/dist/v1alpha2/notifications.js';
const vectors = JSON.parse(readFileSync(new URL('fixtures/alpha38-review-fixes.json', import.meta.url)));
const account = '11111111-1111-4111-8111-111111111111';
const original = { case: 'handle', value: 'mara' };
const record = patch => create(InvitationRecordSchema, { recipient: original, role: 2, state: 1, ...patch });
const now = { seconds: 100n, nanos: 0 };
const spool = id => id ? { id } : undefined;
const rule = id => create(NotificationRuleSchema, { kind: '*', spool: spool(id), channel: 1, delivery: 3 });
const cell = (id, kind) => create(EffectiveDeliverySchema, { kind, spool: spool(id), channel: 1, actorOrigin: 'human' });
const ancestor = (id, readable) => ({ spool: spool(id), readable, systemRoot: false });
const violation = (name, reason, code) => error => error instanceof InvitationError && error.violation === name && error.reason === reason && error.code === code;

test('shared current inviter authority accept/redeem and retry vectors', () => {
  for (const v of vectors.authority) {
    if (v.allowed) validateInviterAuthority(v.offered, v.current);
    else assert.throws(() => validateInviterAuthority(v.offered, v.current), violation('InviterAuthorityLost', 205, 9), v.name);
    for (const state of [1, 2]) {
      const accept = () => planInvitationResponse(record({ role: v.offered, state }), account, account, 'accept', now, true, v.current);
      if (state === 2) assert.deepEqual(accept(), { state: 2, changed: false, grantRole: false });
      else if (v.allowed) accept();
      else assert.throws(accept, violation('InviterAuthorityLost', 205, 9), v.name);
    }
  }
  planInvitationResponse(record(), account, account, 'decline', now, true, 0);
});

test('shared human session guard precedes lookup and terminal replay', () => {
  for (const v of vectors.sessions) for (const action of ['accept', 'decline']) for (const state of [1, 2, 3]) {
    const respond = () => planInvitationResponse(record({ state }), account, account, action, now, v.human, 3);
    if (!v.human) assert.throws(respond, violation('HumanSessionRequired', 204, 7), v.name);
    else if (state === 1) respond();
  }
  for (const action of ['accept', 'decline']) assert.throws(() => planInvitationResponse(record(), undefined, account, action, now, false, 0), violation('HumanSessionRequired', 204, 7));
});

test('large tree projects only local scopes and filtered child provenance', () => {
  const readable = [...Array.from({ length: vectors.descendants }, (_, i) => spool(`child-${i}`)), spool('root')];
  const rules = [rule('root')];
  const request = create(ObserveNotificationsRequestSchema, { includePreferences: true });
  const scopes = notificationProjectionScopes(request, rules, readable);
  assert.deepEqual(scopes.map(s => s?.id), [undefined, 'root']);
  assert.deepEqual(notificationProjectionScopes(request, [rule('root'), rule('root'), rule('hidden'), rule()], readable).map(s => s?.id), [undefined, 'root']);
  const preferences = create(NotificationPreferencesSchema, { rules,
    effectiveDelivery: scopes.flatMap(spool => Array.from({ length: 70 }, (_, i) => ({ spool, kind: `kind-${i}`, channel: 1 }))) });
  assert.equal(preferences.effectiveDelivery.length, 140);
  validateNotificationPreferencesBound(preferences);
  const filtered = create(ObserveNotificationsRequestSchema, { ...request, effectiveDeliverySpool: spool('child-0') });
  assert.deepEqual(notificationProjectionScopes(filtered, rules, readable).map(s => s?.id), ['child-0']);
  for (const readableParent of [true, false]) {
    const ancestors = [ancestor('child-0', true), ancestor('root', readableParent)];
    const resolved = resolveNotificationDelivery(rules, cell('child-0', 'mention'), ancestors, 128, 1, true);
    assert.equal(resolved.source, 3);
    assert.equal(resolved.sourceSpool?.id, readableParent ? 'root' : undefined);
    validateEffectiveDeliverySource(resolved, ancestors, 128);
  }
  for (const invalid of [{ ...filtered, includePreferences: false }, { ...filtered, effectiveDeliverySpool: spool('hidden') }]) {
    assert.throws(() => notificationProjectionScopes(invalid, rules, readable), NotificationValidationError);
  }
});

test('hidden rules and cadence survive replacement until explicit clear', () => {
  const stored = create(NotificationPreferencesSchema, { rules: [rule('hidden'), rule('visible'), rule()],
    digestOverrides: [{ spool: spool('hidden'), digestInterval: { seconds: 3600n, nanos: 0 } }] });
  for (const v of vectors.replacement) {
    const request = create(SetNotificationPreferencesRequestSchema, { preferences: {}, clearUnreadableScopes: v.clear });
    const next = replaceNotificationPreferences(stored, request, [spool('visible')]);
    assert.equal(next.rules.length, v.rules, v.name);
    assert.equal(next.digestOverrides.length, v.overrides, v.name);
    if (!v.clear) assert.deepEqual(next.rules, [rule('hidden')]);
  }
  const unauthorized = create(SetNotificationPreferencesRequestSchema, { preferences: stored });
  assert.throws(() => replaceNotificationPreferences(stored, unauthorized, [spool('visible')]), NotificationValidationError);
  assert.equal(stored.rules.length, 3);
});

test('decline to departed inviter routes account without InvalidSource', () => {
  const ancestors = [ancestor('departed', false), ancestor('parent', true)];
  const declined = cell('departed', 'spool_invitation_declined');
  const rules = [rule(), rule('parent')];
  const resolved = resolveInvitationNotificationDelivery(rules, declined, ancestors, 128, 1, true);
  assert.equal(resolved.spool, undefined);
  assert.equal(resolved.source, 1);
  assert.equal(resolved.delivery, 3);
  assert.equal(resolved.sourceSpool, undefined);
  validateEffectiveDeliverySource(resolved, [], 128);
  assert.throws(() => resolveNotificationDelivery(rules, declined, ancestors, 128, 1, true), NotificationValidationError);
});

test('shared projection privacy gate covers all three read surfaces', () => {
  for (const v of vectors.projections) {
    const invitation = record({ recipient: v.recipient === 'accountId' ? { case: 'accountId', value: account } : original,
      inviter: v.inviter === null ? undefined : { handle: v.inviter }, inviterViaAgentLabel: v.label });
    const event = create(SpoolEventSchema, { payload: { case: 'invitation', value: invitation } });
    const notification = create(NotificationRecordSchema, { invitation });
    const attention = create(AttentionItemSchema, { invitation });
    for (const validate of [() => validateInvitationRecordProjection(invitation, original), () => validateSpoolInvitationProjection(event, original),
      () => validateNotificationInvitationProjection(notification, original), () => validateAttentionInvitationProjection(attention, original)]) {
      if (v.allowed) validate();
      else assert.throws(validate, InvitationError, v.name);
    }
  }
  for (const patch of [{ role: 0 }, { role: 99 }, { state: 0 }, { state: 99 }]) assert.throws(() => validateInvitationRecordProjection(record(patch), original), InvitationError);
  validateInvitationRecordProjection(record({ state: InvitationState.ACCEPTED }), original);
});

test('review fix fields have stable tags and typed defaults', () => {
  assert.equal(ObserveNotificationsRequestSchema.fields.find(f => f.name === 'effective_delivery_spool').number, 5);
  assert.equal(SetNotificationPreferencesRequestSchema.fields.find(f => f.name === 'clear_unreadable_scopes').number, 4);
  assert.equal(create(SetNotificationPreferencesRequestSchema).clearUnreadableScopes, false);
});

test('admin loss revokes every pending offered role and preserves terminal records', async () => {
  const { planInviterAuthorityLoss } = await import('../packages/typescript/dist/v1alpha2/invitation.js');
  const records = [1, 2, 3].flatMap(role => [1, 2, 3, 4, 5].map(state => record({ role, state })));
  assert.deepEqual(planInviterAuthorityLoss(records, 3, now), []);
  for (const role of [0, 1, 2, 99]) {
    const revoked = planInviterAuthorityLoss(records, role, now);
    assert.deepEqual(revoked.map(r => r.role), [1, 2, 3]);
    assert.ok(revoked.every(r => r.state === 4 && r.updatedAt === now));
  }
  assert.equal(records.filter(r => r.state === 1).length, 3);
});
