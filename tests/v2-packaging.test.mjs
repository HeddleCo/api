import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const packageRoot = new URL('../packages/typescript/', import.meta.url);
const distRoot = new URL('dist/v1alpha2/', packageRoot);

// These implementation files intentionally have no dedicated public subpath.
// Schema modules and the two barrel-only helpers remain available through ./v2.
// Keep exact filenames: new modules must receive an export or a reviewed exception.
const barrelOnlyModules = new Set([
  'activity_pb.js',
  'administration_pb.js',
  'analysis_pb.js',
  'behavior_pb.js',
  'billing_pb.js',
  'code_navigation_pb.js',
  'collaboration_pb.js',
  'common_pb.js',
  'content_pb.js',
  'device_pb.js',
  'endpoint_pb.js',
  'identity_pb.js',
  'import_authority_pb.js',
  'integration_pb.js',
  'native_witness_pb.js',
  'owner_records_pb.js',
  'owner_views_pb.js',
  'ownership_pb.js',
  'platform_admin_pb.js',
  'presence_pb.js',
  'provider_internal_pb.js',
  'services_pb.js',
  'stream_pb.js',
  'sync_pb.js',
  'thread_pb.js',
  'timeline_upload_pb.js',
  'views_pb.js',
  'initial-source.js', // Synthetic pre-history helper, exposed through the v2 barrel.
  'thread-ownership.js', // Ownership acceptance helper, exposed through the v2 barrel.
]);
const internalModules = new Set([
  '_collaboration-msgpack.js', // Private canonical MessagePack codec.
  '_hybrid-codec.js', // Private HYBRID signing/canonical-byte codec.
]);

test('every built v2 runtime module has a public export or an explicit exception', () => {
  const manifest = JSON.parse(readFileSync(new URL('package.json', packageRoot), 'utf8'));
  const modules = readdirSync(distRoot, { recursive: true })
    .filter(name => /\.(?:js|mjs|cjs)$/.test(name)).sort();
  assert.ok(modules.length > 0, 'Build the TypeScript package before testing packaging');
  const targets = new Set();
  for (const [subpath, entry] of Object.entries(manifest.exports)) {
    if (subpath !== './v2' && !subpath.startsWith('./v2/')) continue;
    const target = typeof entry === 'string' ? entry : entry.import ?? entry.default;
    assert.equal(typeof target, 'string', `Missing ESM import target for ${subpath}`);
    assert.ok(existsSync(new URL(target, packageRoot)), `Missing runtime target for ${subpath}`);
    const types = typeof entry === 'string' ? target.replace(/\.js$/, '.d.ts') : entry.types;
    assert.equal(typeof types, 'string', `Missing types target for ${subpath}`);
    assert.ok(existsSync(new URL(types, packageRoot)), `Missing declarations for ${subpath}`);
    targets.add(fileURLToPath(new URL(target, packageRoot)));
  }
  assert.ok(targets.has(fileURLToPath(new URL('index.js', distRoot))), 'Missing public ./v2 barrel');
  const barrel = readFileSync(new URL('index.js', distRoot), 'utf8');
  for (const name of [...barrelOnlyModules, ...internalModules]) {
    assert.ok(modules.includes(name), `Stale packaging exception: ${name}`);
    if (barrelOnlyModules.has(name)) {
      assert.ok(barrel.includes(`export * from "./${name}";`), `Missing barrel export for ${name}`);
    }
  }
  const missing = modules.filter(name =>
    !targets.has(fileURLToPath(new URL(name, distRoot))) &&
    !barrelOnlyModules.has(name) && !internalModules.has(name));
  assert.deepEqual(missing, [], `Missing public exports for built v2 runtime modules: ${missing.join(', ')}`);
});

test('npm public import-authority export includes alpha33 one-shot helpers', async () => {
  const runtime = await import('@heddleco/api/v2/import-authority');
  assert.equal(typeof runtime.verifyImportBundleWitnesses, 'function');
  assert.equal(typeof runtime.effectiveOwnerAuthorityExpiry, 'function');
  assert.equal(typeof runtime.remainingImportScope, 'function');
  assert.equal(typeof runtime.checkImportRetryAdmission, 'function');
  assert.equal(runtime.originalImportRetryUnavailable, undefined);
  assert.equal(runtime.verifyImportRenewal, undefined);
  assert.equal(runtime.signImportRenewal, undefined);
  assert.equal(typeof runtime.validateRepositorySizeEstimate, 'function');
});
