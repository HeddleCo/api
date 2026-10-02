import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import * as v2 from '../packages/typescript/dist/v1alpha2/index.js';

const vectors = JSON.parse(readFileSync(new URL('./fixtures/code-navigation-v2.json', import.meta.url)));
function decode(name, schema) {
  const bytes = new Uint8Array(Buffer.from(vectors[name], 'hex'));
  const result = fromBinary(schema, bytes);
  assert.deepEqual(toBinary(schema, result), bytes, `stable wire vector ${name}`);
  return result;
}

test('navigation vectors retain outlines, exact positions and unresolved occurrences', () => {
  const outline = decode('outline', v2.GetFileSymbolsResponseSchema);
  assert.equal(outline.metadata.indexPresent, true);
  assert.equal(outline.metadata.attestation, v2.SemanticAttestation.CLIENT_ATTESTED);
  assert.equal(outline.symbols[0].address.definitionIndex, 0);
  assert.equal(outline.symbols[0].span.startByte, undefined, 'line-only evidence stays line-only');
  assert.equal(outline.symbols[0].semanticHash.length, 32);
  const definition = decode('definition', v2.GetDefinitionResponseSchema);
  assert.deepEqual(definition.outcome.value, outline.symbols[0]);
  assert.equal(definition.outcome.case, 'definition');
  assert.equal(definition.occurrence.span.startByte, 12n);
  const unresolved = decode('unresolved', v2.GetDefinitionResponseSchema);
  assert.equal(unresolved.metadata.resolverPresent, false);
  assert.equal(unresolved.metadata.attestation, v2.SemanticAttestation.CLIENT_ATTESTED);
  assert.equal(unresolved.outcome.case, 'reason');
  assert.equal(unresolved.outcome.value, v2.CodeNavigationReason.NO_RESOLVER_FOR_LANGUAGE);
  assert.deepEqual(unresolved.occurrence, definition.occurrence);
  const position = decode('position', v2.GetDefinitionRequestSchema).at.position;
  assert.equal(position.byteOffset, 0n, 'offset zero retains presence');
  assert.equal(create(v2.CodePositionSchema).byteOffset, undefined, 'missing offset differs from zero');
  assert.equal(position.line, 1);
  assert.equal(position.column, 1);
  const absent = decode('no_index', v2.GetFileSymbolsResponseSchema);
  assert.equal(absent.reason, v2.CodeNavigationReason.NO_INDEX);
  assert.equal(absent.metadata.indexPresent, false);
  assert.equal(absent.metadata.attestation, v2.SemanticAttestation.UNSPECIFIED);
  assert.equal(absent.page.exhausted, false);
});

test('graph vectors keep oriented edges, paging and hop truncation independent', () => {
  const refs = decode('refs', v2.GetSemanticRefsResponseSchema);
  assert.equal(refs.refs[0].kind, v2.CodeEdgeKind.CALLS);
  assert.equal(refs.refs[0].source.path, 'src/main.rs');
  assert.equal(refs.refs[0].target.address.path, 'src/lib.rs');
  assert.equal(refs.refs[0].hop, 1);
  assert.equal(refs.truncated, true);
  assert.deepEqual(refs.page.nextPage, new Uint8Array([9, 10]));
  assert.equal(refs.page.exhausted, false);
  const importers = decode('importers', v2.GetSemanticImportersResponseSchema);
  assert.equal(importers.importers[0].path, 'src/main.rs');
  assert.equal(importers.importers[0].hop, 1);
  assert.equal(importers.truncated, false);
  assert.equal(importers.page.exhausted, true);
});

test('ingestion vectors bind attachment, full object inventory, source tree and hard limits', () => {
  const open = decode('publication', v2.PublishContentOpenSchema);
  const ready = decode('ready', v2.TransferReadySchema);
  assert.deepEqual(open.semanticIndexes, ready.semanticIndexes);
  const manifest = open.semanticIndexes[0];
  assert.equal(manifest.attachment.algorithm, 'state-attachment');
  assert.equal(manifest.sourceTreeHash.length, 32);
  assert.equal(manifest.objects.length, 2);
  assert.deepEqual(manifest.rootHash, manifest.objects[0].hash);
  assert.deepEqual(manifest.objects.map(object => object.size), [20n, 30n]);
  assert.equal(ready.semanticIndexLimits.maxNodes, 100000);
  assert.equal(ready.semanticIndexLimits.maxBytes, 67108864n);
  assert.equal(ready.semanticIndexLimits.maxDepth, 64);
  assert.equal(create(v2.TransferReadySchema).semanticIndexLimits, undefined, 'older endpoints advertise no ingestion');
  assert.equal(create(v2.PublishContentOpenSchema).semanticIndexes.length, 0);
  assert.equal(decode('fetch', v2.TransferSelectionSchema).includeSemanticIndex, true);
  assert.equal(create(v2.TransferSelectionSchema).includeSemanticIndex, false);
});
