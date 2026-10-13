import assert from 'node:assert/strict';
import { test } from 'node:test';
import { create, getOption } from '@bufbuild/protobuf';
import { MandatoryProtocolFeature as F, ProtocolCompatibilitySchema, rpc_contract } from '../packages/typescript/dist/common/contract_pb.js';
import { hostSupports, requireFeature, MissingProtocolFeatureError } from '../packages/typescript/dist/v1alpha2/protocol.js';
import { createServiceClient } from '../packages/typescript/dist/v1alpha2/client.js';
import { CollaborationService, ContentService } from '../packages/typescript/dist/v1alpha2/services_pb.js';
import { validateOutlineRead } from '../packages/typescript/dist/v1alpha2/content.js';
import { canonicalMention, validateEntityMentions } from '../packages/typescript/dist/v1alpha2/collaboration.js';
import { OutlineReadSchema } from '../packages/typescript/dist/v1alpha2/content_pb.js';
import { EntityRefSchema } from '../packages/typescript/dist/v1alpha2/common_pb.js';
import { requireHybridPeer } from '../packages/typescript/dist/v1alpha2/import-authority.js';
const peer = create(ProtocolCompatibilitySchema, { protocolVersion: 2, mandatoryFeatures: [1, 2, 3, 4] });
const missing = create(ProtocolCompatibilitySchema, { protocolVersion: 2, mandatoryFeatures: [1] });
const refusal = feature => e => e instanceof MissingProtocolFeatureError && e.feature === feature;

test('feature numbers are stable and support means advertised set membership', () => {
  assert.deepEqual([F.UNSPECIFIED, F.IMPORT_AUTHORITY_HOST_WITNESS_V1, F.COLLABORATION_MENTIONS_V1, F.DISCUSSION_TAGS_V1, F.CONTENT_OUTLINE_V1], [0, 1, 2, 3, 4]);
  for (const feature of [2, 3, 4]) {
    assert.equal(hostSupports(peer, feature), true);
    requireFeature(peer, feature);
    for (const absent of [undefined, missing]) {
      assert.equal(hostSupports(absent, feature), false);
      assert.throws(() => requireFeature(absent, feature), refusal(feature));
    }
  }
  assert.equal(hostSupports(create(ProtocolCompatibilitySchema, { mandatoryFeatures: [0] }), F.UNSPECIFIED), false);
  requireHybridPeer(peer);
  for (const service of [CollaborationService, ContentService]) {
    for (const method of service.methods) assert.ok(getOption(method, rpc_contract).mandatoryFeatures.every(f => ![2, 3, 4].includes(f)));
  }
});

test('outline and delivery mention validators require only their own feature', () => {
  const read = create(OutlineReadSchema, { path: 'main.rs' });
  validateOutlineRead(read, peer);
  const mention = create(EntityRefSchema, { entity: { case: 'principal', value: { id: '00000000-0000-0000-0000-000000000001' } } });
  canonicalMention(mention, peer); validateEntityMentions([mention], peer);
  for (const absent of [undefined, missing]) {
    assert.throws(() => validateOutlineRead(read, absent), refusal(4));
    assert.throws(() => canonicalMention(mention, absent), refusal(2));
    assert.throws(() => validateEntityMentions([mention], absent), refusal(2));
    validateEntityMentions([], absent);
  }
});

test('typed client gates open/reply/context/extraction/tag edits/outline before transport', async () => {
  const mentions = [{ entity: { case: 'principal', value: { id: '00000000-0000-0000-0000-000000000001' } } }];
  const cases = [
    [CollaborationService, 'openDiscussion', { mentions }, 2],
    [CollaborationService, 'appendTurn', { mentions }, 2],
    [CollaborationService, 'putContext', { context: { mentions } }, 2],
    [CollaborationService, 'resolveDiscussion', { resolution: { case: 'extractContext', value: { mentions } } }, 2],
    [CollaborationService, 'openDiscussion', { tags: [{ tag: { case: 'text', value: 'tag' } }] }, 3],
    [CollaborationService, 'editDiscussionTags', { tags: [] }, 3],
    [ContentService, 'readContent', { selections: [{ selection: { case: 'outline', value: { path: 'main.rs' } } }] }, 4],
  ];
  for (const [service, name, input, feature] of cases) {
    const method = service.method[name];
    const path = `/${service.typeName}/${method.name}`;
    let calls = 0;
    const transport = {
      async unary() { calls++; return new Uint8Array(); },
      async *open(_method, requests) { calls++; for await (const _ of requests) {} },
    };
    const consume = async (protocol, request) => {
      const result = createServiceClient(service, transport, new Set([path]), protocol)[name]({ clientOperationId: 'op', ...request });
      if (method.methodKind === 'unary') await result;
      else for await (const _ of result) {}
    };
    for (const absent of [undefined, missing]) await assert.rejects(consume(absent, input), refusal(feature));
    assert.equal(calls, 0);
    await consume(create(ProtocolCompatibilitySchema, { mandatoryFeatures: [feature] }), input);
    assert.equal(calls, 1);
    if (name !== 'editDiscussionTags') {
      await consume(undefined, {});
      assert.equal(calls, 2);
    }
  }
});
