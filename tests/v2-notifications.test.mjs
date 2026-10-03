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
