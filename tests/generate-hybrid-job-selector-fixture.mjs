// Maintenance only. Tests consume the checked-in vectors without regenerating them.
import { create, toBinary } from '@bufbuild/protobuf';
import { writeFileSync } from 'node:fs';
import { OperationRecordSchema, GetImportJobStateRequestSchema } from '../packages/typescript/dist/v1alpha2/index.js';

const logicalJobId = new Uint8Array(16).fill(0x24);
const spool = '11111111-1111-1111-1111-111111111111';
const first = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const hex = (schema, value) => Buffer.from(toBinary(schema, create(schema, value))).toString('hex');
const operations = [];
function add(name, expected = 'OK', options = {}) {
  const { selector = logicalJobId, destination = spool, subject = true,
    emptySubject = false, sourceHidden = false, missingRef = false, retry, physical = first } = options;
  const ref = id => ({ ...(destination !== null ? { spool: { id: destination } } : {}), id });
  const value = {
    ...(missingRef ? {} : { ref: ref(physical) }), clientOperationId: `caller-operation-${name}`,
    version: new Uint8Array([1]), state: 1,
    ...(subject ? { subject: emptySubject ? {} : { subject: { case: 'import', value: {
      ...(!sourceHidden ? { sourceUrl: 'https://example.com/repo.git' } : {}),
      ...(selector !== null ? { hybridJob: { logicalJobId: selector } } : {}),
    } } } } : {}),
    ...(retry ? { retryOf: ref(retry) } : {}),
  };
  operations.push({ name, wire_hex: hex(OperationRecordSchema, value), expected,
    ...(expected === 'OK' ? { request_wire_hex: hex(GetImportJobStateRequestSchema,
      { destination: { id: destination }, logicalJobId: selector }) } : {}),
  });
}
add('initial');
add('retry', 'OK', { retry: first, physical: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' });
add('renewal', 'OK', { retry: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', physical: 'cccccccc-cccc-cccc-cccc-cccccccccccc' });
add('same-job-id-other-destination', 'OK', { destination: '22222222-2222-2222-2222-222222222222' });
add('non-nil-with-zero-octets', 'OK', { selector: Uint8Array.from([1, ...new Array(15).fill(0)]) });
add('non-hybrid', 'unavailable', { selector: null });
add('before-durable-association', 'unavailable', { selector: null });
add('subject-unavailable', 'unavailable', { subject: false });
add('subject-case-unavailable', 'unavailable', { emptySubject: true });
for (const size of [0, 15, 17, 32]) add(`wrong-job-width-${size}`, 'Canonical', { selector: new Uint8Array(size).fill(0x24) });
add('nil-job-id', 'Canonical', { selector: new Uint8Array(16) });
for (const [name, destination] of [['missing', null], ['empty', ''], ['nil', '00000000-0000-0000-0000-000000000000'],
  ['malformed', 'spool-name'], ['uppercase', 'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA']]) {
  add(`${name}-destination`, 'Scope', { destination });
}
add('source-hidden-selector-visible', 'OK', { sourceHidden: true });
add('missing-operation-ref', 'Scope', { missingRef: true });
writeFileSync('tests/fixtures/hybrid-job-selector-v1.json', JSON.stringify({ format: 'hybrid-job-selector-v1', operations }, null, 2) + '\n');
console.log(`wrote ${operations.length} shared selector vectors`);
