import { fromBinary, toBinary, create } from '@bufbuild/protobuf';
import { FileDescriptorSetSchema, FileDescriptorProtoSchema } from '@bufbuild/protobuf/wkt';
import { readFileSync, writeFileSync } from 'node:fs';
// Historical input only. Do not refresh from the current schema.
// buf build '.git#ref=54f3e3fd16ddf319c06d990f6fa691fdd12c8182' -o /tmp/alpha15.binpb
// node tests/freeze-cleanup-lane-alpha15.mjs /tmp/alpha15.binpb
if (!process.argv[2]) throw new Error('Pass the original alpha.15 descriptor path');
const src = fromBinary(FileDescriptorSetSchema, readFileSync(process.argv[2]));
const types = new Map();
for (const f of src.file) {
  const nested = (m, prefix, top) => {
    types.set(prefix, { f, item: top, isEnum: false });
    for (const e of m.enumType) types.set(`${prefix}.${e.name}`, { f, item: top, isEnum: false });
    for (const n of m.nestedType) nested(n, `${prefix}.${n.name}`, top);
  };
  for (const m of f.messageType) nested(m, `.${f.package}.${m.name}`, m);
  for (const e of f.enumType) types.set(`.${f.package}.${e.name}`, { f, item: e, isEnum: true });
}
const queue = ['SpoolOverview','ContextRecord','DiscussionTurn','ProviderRepository','ActionAvailability','SearchHit','ThreadRelationship','Blocked','MutationReceipt','ObserveIntegrationsRequest','CaptureSummary'].map(n => `.heddle.api.v1alpha2.${n}`);
queue.push('.heddle.api.common.CallFailure');
const selected = new Map(), seen = new Set();
const walk = (m, cb) => { for (const fld of m.field) if (fld.typeName) cb(fld.typeName); for (const n of m.nestedType) walk(n, cb); };
while (queue.length) {
  const name = queue.pop();
  if (seen.has(name)) continue;
  seen.add(name);
  const entry = types.get(name);
  if (!entry) throw Error(`Missing ${name}`);
  const { f, item, isEnum } = entry;
  selected.set(`${f.name}:${item.name}`, entry);
  if (!isEnum) walk(item, name => queue.push(name));
}
const strip = item => {
  delete item.options;
  for (const fld of item.field ?? []) delete fld.options;
  for (const nested of item.nestedType ?? []) strip(nested);
  for (const e of item.enumType ?? []) strip(e);
  for (const v of item.value ?? []) delete v.options;
};
const files = [];
for (const f of src.file) {
  const items = [...selected.values()].filter(x => x.f.name === f.name);
  if (!items.length) continue;
  const dependencies = new Set();
  for (const x of items) if (!x.isEnum) walk(x.item, name => { const dep = types.get(name).f.name; if (dep !== f.name) dependencies.add(dep); });
  const dest = create(FileDescriptorProtoSchema, { name: f.name, package: f.package, syntax: f.syntax, dependency: [...dependencies].sort(),
    messageType: items.filter(x => !x.isEnum).map(x => x.item), enumType: items.filter(x => x.isEnum).map(x => x.item) });
  for (const x of [...dest.messageType, ...dest.enumType]) strip(x);
  files.push(dest);
}
const wire = toBinary(FileDescriptorSetSchema, create(FileDescriptorSetSchema, { file: files }));
writeFileSync(new URL('./fixtures/cleanup-lane-alpha15.binpb', import.meta.url), wire);
console.log(`Frozen alpha.15: ${files.length} files, ${selected.size} types, ${wire.length} bytes`);
