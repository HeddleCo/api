import { writeFileSync } from 'node:fs';
import { create, toBinary } from '@bufbuild/protobuf';
import * as v2 from '../packages/typescript/dist/v1alpha2/index.js';

// Wire-shape vectors, not admitted semantic payloads. Downstream handlers must
// validate canonical objects, tree binding and live authorization separately.
const hash = value => new Uint8Array(32).fill(value);
const spool = { id: '00000000-0000-0000-0000-000000000001' };
const thread = { spool, id: { value: hash(2) } };
const revision = { spool, revision: { case: 'state', value: { value: hash(3) } } };
const metadata = {
  revision, thread, indexPresent: true, resolverPresent: true, language: 'rust',
  attestation: v2.SemanticAttestation.CLIENT_ATTESTED,
  resolvers: [{ language: 'rust', resolverPresent: true }], attachmentHash: hash(4),
};
const symbol = {
  address: { path: 'src/lib.rs', symbolId: 'answer', definitionIndex: 0 },
  name: 'answer', kind: v2.CodeSymbolKind.FUNCTION,
  span: { startLine: 1, endLine: 3 }, semanticHash: hash(5),
};
const occurrence = {
  path: 'src/main.rs', localId: 0, name: 'answer', role: v2.CodeOccurrenceRole.CALL,
  span: { startLine: 2, endLine: 2, startByte: 12n, endByte: 18n },
  enclosingSymbol: { path: 'src/main.rs', symbolId: 'main', definitionIndex: 0 },
};
const manifest = {
  attachment: { algorithm: 'state-attachment', digest: hash(4) },
  rootHash: hash(6), sourceTreeHash: hash(7),
  objects: [{ hash: hash(6), size: 20n }, { hash: hash(8), size: 30n }],
};
const vectors = {};
function vector(name, schema, input) {
  vectors[name] = Buffer.from(toBinary(schema, create(schema, input))).toString('hex');
}
vector('outline', v2.GetFileSymbolsResponseSchema, { metadata, symbols: [symbol], page: { exhausted: true } });
vector('definition', v2.GetDefinitionResponseSchema, { metadata, occurrence, outcome: { case: 'definition', value: symbol } });
vector('unresolved', v2.GetDefinitionResponseSchema, {
  metadata: { ...metadata, resolverPresent: false, language: 'python', resolvers: [{ language: 'python' }] },
  occurrence, outcome: { case: 'reason', value: v2.CodeNavigationReason.NO_RESOLVER_FOR_LANGUAGE },
});
vector('no_index', v2.GetFileSymbolsResponseSchema, {
  metadata: { revision, thread }, page: { exhausted: false }, reason: v2.CodeNavigationReason.NO_INDEX,
});
vector('refs', v2.GetSemanticRefsResponseSchema, {
  metadata, refs: [{ source: occurrence, target: symbol, kind: v2.CodeEdgeKind.CALLS, hop: 1 }],
  page: { nextPage: new Uint8Array([9, 10]), exhausted: false }, truncated: true,
});
vector('importers', v2.GetSemanticImportersResponseSchema, {
  metadata, importers: [{ path: 'src/main.rs', hop: 1 }], page: { exhausted: true },
});
vector('position', v2.GetDefinitionRequestSchema, {
  revision, thread, at: { path: 'src/lib.rs', position: { byteOffset: 0n, line: 1, column: 1 } },
});
vector('publication', v2.PublishContentOpenSchema, { thread, revision, semanticIndexes: [manifest] });
vector('ready', v2.TransferReadySchema, {
  thread, current: revision, semanticIndexes: [manifest],
  semanticIndexLimits: { maxNodes: 100000, maxBytes: 67108864n, maxDepth: 64 },
});
vector('fetch', v2.TransferSelectionSchema, { includeSemanticIndex: true });
writeFileSync(new URL('../tests/fixtures/code-navigation-v2.json', import.meta.url), `${JSON.stringify(vectors, null, 2)}\n`);
