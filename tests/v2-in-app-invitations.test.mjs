import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import {
  InvitationRecordSchema, InvitationState, AcceptInvitationRequestSchema, DeclineInvitationRequestSchema,
  CreateInvitationRequestSchema, CreateInvitationResponseSchema,
} from '../packages/typescript/dist/v1alpha2/administration_pb.js';
import { NotificationRecordSchema, AttentionItemSchema } from '../packages/typescript/dist/v1alpha2/activity_pb.js';
import { ActionAvailabilitySchema, Capability } from '../packages/typescript/dist/v1alpha2/common_pb.js';
import {
  InvitationError, resolveInvitationRecipient, planInvitationResponse, validateCreateInvitation, validateCreateInvitationResponse,
  SPOOL_INVITATION, SPOOL_INVITATION_DECLINED,
} from '../packages/typescript/dist/v1alpha2/invitation.js';

const vectors = JSON.parse(readFileSync(new URL('fixtures/in-app-invitations.json', import.meta.url)));
const recipient = v => v.kind === 'none' ? { case: undefined } :
  { case: v.kind === 'account_id' ? 'accountId' : v.kind, value: v.value };
const account = '11111111-1111-4111-8111-111111111111';
const now = { seconds: 100n, nanos: 0 };
test('shared typed recipient wire vectors retire the old string tag', () => {
  for (const v of vectors.wire) {
    const record = create(InvitationRecordSchema, { recipient: recipient(v), state: v.state });
    const wire = Buffer.from(v.hex, 'hex');
    assert.deepEqual(Buffer.from(toBinary(InvitationRecordSchema, record)), wire, v.name);
    assert.deepEqual(fromBinary(InvitationRecordSchema, wire), record);
  }
  assert.equal(fromBinary(InvitationRecordSchema, Buffer.from('1a046d617261', 'hex')).recipient.case, undefined);
});

function refusal(fn, v) {
  assert.throws(fn, error => {
    assert.ok(error instanceof InvitationError);
    const failure = error.failure();
    if (v.reason === 302) assert.equal(failure.message, 'no such user');
    if (v.reason === 300) assert.equal(failure.message, 'invitation unavailable');
    assert.equal(failure.code, v.code, v.name);
    assert.equal(failure.error.reason, v.reason, v.name);
    assert.equal(failure.error.field, v.field, v.name);
    assert.equal(failure.error.resource, '');
    assert.equal(failure.error.context.case, undefined);
    return true;
  });
}

test('shared recipient vectors preserve typed refusal and private handle binding', () => {
  for (const v of vectors.recipient) {
    const record = create(InvitationRecordSchema, { recipient: recipient(v) });
    const resolve = () => resolveInvitationRecipient(record, handle => {
      assert.equal(handle, v.lookup ?? v.value.trim().replace(/[A-Z]/g, c => c.toLowerCase()));
      return v.resolved ?? undefined;
    });
    if (v.code) refusal(resolve, v);
    else assert.equal(resolve(), v.account ?? undefined, v.name);
  }
});

test('shared signed-in accept/decline vectors check authorization before terminal state', () => {
  for (const v of vectors.response) {
    const record = create(InvitationRecordSchema, {
      recipient: recipient(v), role: 1, state: v.state,
      expiresAt: v.expires_seconds === undefined ? undefined :
        { seconds: BigInt(v.expires_seconds), nanos: v.expires_nanos },
    });
    const respond = () => planInvitationResponse(record, v.stored ?? undefined, v.caller ?? undefined,
      v.action, { seconds: BigInt(v.now_seconds), nanos: v.now_nanos }, true, 3);
    if (v.code) refusal(respond, v);
    else {
      const plan = respond();
      assert.equal(plan.state, v.expected_state, v.name);
      assert.equal(plan.changed, v.changed, v.name);
      assert.equal(plan.grantRole, v.grant_role, v.name);
      assert.equal(plan.notificationKind, v.notification ?? undefined, v.name);
    }
  }
});

test('two declines produce one notification, and retry never grants a role', () => {
  const record = create(InvitationRecordSchema, { recipient: { case: 'handle', value: 'mara' }, state: InvitationState.PENDING });
  let notifications = 0;
  for (let i = 0; i < 2; i++) {
    const plan = planInvitationResponse(record, account, account, 'decline', now, true, 3);
    record.state = plan.state;
    notifications += plan.notificationKind === SPOOL_INVITATION_DECLINED ? 1 : 0;
    assert.equal(plan.grantRole, false);
  }
  assert.equal(record.state, InvitationState.DECLINED);
  assert.equal(notifications, 1);
});

test('inbox and attention reuse typed invitation subject and projection without resolved UUID', () => {
  const invitation = create(InvitationRecordSchema, {
    ref: { id: 'invitation-id' }, recipient: { case: 'handle', value: 'mara' },
    role: 2, state: InvitationState.PENDING, spoolName: 'Example',
    inviter: { handle: 'alice', displayName: 'Alice' }, inviterViaAgentLabel: 'helper',
  });
  const actions = [
    ['AcceptInvitation', Capability.ACCEPT_INVITATION],
    ['DeclineInvitation', Capability.DECLINE_INVITATION],
  ].map(([method, capability]) => create(ActionAvailabilitySchema, {
    method: `/heddle.api.v1alpha2.SpoolService/${method}`, capability,
    implemented: true, authorized: true,
    endpoint: { publicKey: new Uint8Array(32).fill(1), kind: 1 },
    target: { entity: { case: 'invitation', value: invitation.ref } },
  }));
  for (const [schema, data] of [
    [NotificationRecordSchema, { kind: SPOOL_INVITATION, title: 'Invited to Example as writer by alice', invitation }],
    [AttentionItemSchema, { kind: SPOOL_INVITATION, headline: 'Invited to Example as writer by alice', invitation }],
  ]) {
    const wire = toBinary(schema, create(schema, { ...data, actions, subject: { entity: { case: 'invitation', value: invitation.ref } } }));
    assert.equal(Buffer.from(wire).includes(Buffer.from(account)), false);
    const decoded = fromBinary(schema, wire);
    assert.equal(decoded.subject.entity.case, 'invitation');
    assert.equal(decoded.invitation.recipient.case, 'handle');
    assert.equal(decoded.invitation.inviter.handle, 'alice');
    assert.deepEqual(decoded.actions.map(a => [a.method, a.capability]), actions.map(a => [a.method, a.capability]));
    assert.equal(decoded.actions.every(a => a.target.entity.case === 'invitation'), true);
  }
});

test('create validator rejects projection fields and accepts typed inputs', () => {
  const record = create(InvitationRecordSchema, { recipient: { case: 'handle', value: 'mara' }, role: 1 });
  validateCreateInvitation(record);
  for (const patch of [{state: 1}, {version: new Uint8Array([1])}, {spoolName: 'private'}, {inviter: {handle: 'alice'}}, {role: 99}]) {
    assert.throws(() => validateCreateInvitation(create(InvitationRecordSchema, { ...record, ...patch })), InvitationError);
  }
  assert.deepEqual(AcceptInvitationRequestSchema.fields.map(f => [f.name, f.number]), [['client_operation_id', 1], ['invitation', 2]]);
  assert.deepEqual(DeclineInvitationRequestSchema.fields.map(f => [f.name, f.number]), [['client_operation_id', 1], ['invitation', 2]]);
});

test('create response privacy gate rejects replacing a handle with its UUID or link', () => {
  const invitation = create(InvitationRecordSchema, { recipient: { case: 'handle', value: 'mara' }, role: 1 });
  const request = create(CreateInvitationRequestSchema, { invitation });
  const response = create(CreateInvitationResponseSchema, {
    invitation: { ...invitation, state: InvitationState.PENDING },
  });
  validateCreateInvitationResponse(request, response);
  assert.throws(() => validateCreateInvitationResponse(request, create(CreateInvitationResponseSchema, {
    ...response, invitation: { ...response.invitation, recipient: { case: 'accountId', value: account } },
  })), InvitationError);
  assert.throws(() => validateCreateInvitationResponse(request, { ...response, redemptionSecret: new Uint8Array([1]) }), InvitationError);
  for (const kind of ['email', 'accountId']) {
    const value = kind === 'email' ? 'mara@example.org' : account;
    const input = create(CreateInvitationRequestSchema, { invitation: { ...invitation, recipient: { case: kind, value } } });
    const output = create(CreateInvitationResponseSchema, { invitation: { ...input.invitation, state: 1 },
      redemptionSecret: kind === 'email' ? new Uint8Array([1]) : undefined });
    validateCreateInvitationResponse(input, output);
    assert.throws(() => validateCreateInvitationResponse(input, { ...output,
      redemptionSecret: kind === 'email' ? new Uint8Array() : new Uint8Array([1]) }), InvitationError);
  }
});
