import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { create, fromBinary } from "@bufbuild/protobuf";
import {
  TreadleArgvSchema,
  TreadleCheckClass,
  TreadleCheckSchema,
  TreadleDefinitionSchema,
  TreadleDeterminismClass,
  TreadleEnvEntrySchema,
  TreadleIsolationHintsSchema,
  TreadleJobSchema,
  TreadleMatrixValueSchema,
  TreadleNetworkAccess,
  TreadlePlatformSchema,
  TreadleRetrySchema,
  TreadleSecretRefSchema,
  TreadleSecretTier,
  TreadleServiceContainerSchema,
  TreadleTargetEnvironmentSchema,
  TreadleTriggerKind,
  TreadleTriggerSchema,
} from "../packages/typescript/dist/treadle_pb.js";
import {
  canonicalTreadleDefinitionBytes,
  treadleDefinitionBlake3,
} from "../packages/typescript/dist/treadle.js";
import {
  defineCheck,
  definePipeline,
  defineService,
  emitPipeline,
  job,
  matrix,
  secretRef,
} from "../packages/typescript/dist/treadle-authoring.js";

const literalEnv = (name, value) =>
  create(TreadleEnvEntrySchema, {
    name,
    source: { case: "literalValue", value },
  });
const secretEnv = (name, value) =>
  create(TreadleEnvEntrySchema, {
    name,
    source: { case: "secretRef", value },
  });
const trigger = (kind, cronExpression = "") =>
  create(TreadleTriggerSchema, { kind, cronExpression });
const retry = (maxRetries, flakeSignatures = []) =>
  create(TreadleRetrySchema, { maxRetries, flakeSignatures });
const isolation = (networkAccess, fields = {}) =>
  create(TreadleIsolationHintsSchema, { networkAccess, ...fields });
const sha256Digest = (hexDigit) => `sha256:${hexDigit.repeat(64)}`;
const targetEnvironment = (hexDigit, os, arch) =>
  create(TreadleTargetEnvironmentSchema, {
    ociImageDigest: sha256Digest(hexDigit),
    platform: create(TreadlePlatformSchema, { os, arch }),
  });

// Intentionally unordered: canonicalization, rather than fixture construction,
// owns every set-like ordering decision.
const definition = create(TreadleDefinitionSchema, {
  formatVersion: 1,
  name: "heddle-ci",
  secretRefs: [
    create(TreadleSecretRefSchema, {
      name: "registry-token",
      provider: "vault",
      tier: TreadleSecretTier.TRUSTED_RUNNER_ONLY,
    }),
    create(TreadleSecretRefSchema, {
      name: "db-password",
      tier: TreadleSecretTier.STANDARD,
    }),
  ],
  services: [
    create(TreadleServiceContainerSchema, {
      name: "postgres",
      image: "postgres:16",
      ports: [5433, 5432],
      env: [
        literalEnv("POSTGRES_DB", "treadle"),
        secretEnv("POSTGRES_PASSWORD", "db-password"),
      ],
      readiness: create(TreadleArgvSchema, {
        command: "pg_isready",
        args: ["-U", "treadle"],
      }),
      ociImageDigest: sha256Digest("4"),
    }),
  ],
  jobs: [
    create(TreadleJobSchema, {
      name: "test-linux",
      matrix: [
        create(TreadleMatrixValueSchema, { name: "toolchain", value: "stable" }),
        create(TreadleMatrixValueSchema, { name: "target", value: "x86_64-unknown-linux-gnu" }),
      ],
      checks: [
        create(TreadleCheckSchema, {
          name: "unit",
          command: "cargo",
          args: ["test", "--locked"],
          class: TreadleCheckClass.REQUIRED,
          timeoutSeconds: 1800,
          env: [
            secretEnv("REGISTRY_TOKEN", "registry-token"),
            literalEnv("RUST_LOG", "info"),
            literalEnv("CARGO_TERM_COLOR", "always"),
          ],
          workingDirectory: "",
          serviceDependencies: ["postgres"],
          retry: retry(2, ["connection reset", "timed out"]),
          cachePaths: ["target/debug", "target"],
          isolation: isolation(TreadleNetworkAccess.SERVICES_ONLY, {
            profile: "linux-medium",
            cpuMillis: 2000,
            memoryBytes: 4_294_967_296n,
            processLimit: 256,
          }),
          triggers: [
            trigger(TreadleTriggerKind.MANUAL),
            trigger(TreadleTriggerKind.CRON, "0 3 * * 1"),
            trigger(TreadleTriggerKind.PUSH),
          ],
          supersedeOlderRuns: true,
          targetEnvironment: targetEnvironment("1", "linux", "amd64"),
          determinismClass: TreadleDeterminismClass.DETERMINISTIC,
        }),
        create(TreadleCheckSchema, {
          name: "lint",
          command: "cargo",
          args: ["clippy", "--", "-D", "warnings"],
          class: TreadleCheckClass.ADVISORY,
          timeoutSeconds: 900,
          workingDirectory: "crates/core",
          retry: retry(0),
          isolation: isolation(TreadleNetworkAccess.NONE),
          triggers: [trigger(TreadleTriggerKind.PUSH)],
          supersedeOlderRuns: false,
          targetEnvironment: targetEnvironment("2", "linux", "arm64"),
          determinismClass: TreadleDeterminismClass.DETERMINISTIC,
        }),
      ],
    }),
    create(TreadleJobSchema, {
      name: "docs",
      checks: [
        create(TreadleCheckSchema, {
          name: "build",
          command: "npm",
          args: ["run", "docs"],
          class: TreadleCheckClass.INFORMATIONAL,
          timeoutSeconds: 600,
          workingDirectory: "docs",
          retry: retry(0),
          isolation: isolation(TreadleNetworkAccess.FULL),
          triggers: [trigger(TreadleTriggerKind.MANUAL)],
          supersedeOlderRuns: true,
          targetEnvironment: targetEnvironment("3", "linux", "amd64"),
          determinismClass: TreadleDeterminismClass.NONDETERMINISTIC,
        }),
      ],
    }),
  ],
});

const canonicalHex = Buffer.from(canonicalTreadleDefinitionBytes(definition)).toString("hex");
const blake3Hex = Buffer.from(treadleDefinitionBlake3(definition)).toString("hex");

const sdkDbPassword = secretRef({ name: "db-password", tier: "standard" });
const sdkRegistryToken = secretRef({
  name: "registry-token",
  provider: "vault",
  tier: "trusted-runner-only",
});

const sdkUnitCheck = (reordered = false) => defineCheck({
  name: "unit",
  command: "cargo",
  args: ["test", "--locked"],
  class: "required",
  timeoutSeconds: 1800,
  env: reordered
    ? { CARGO_TERM_COLOR: "always", RUST_LOG: "info", REGISTRY_TOKEN: sdkRegistryToken }
    : { REGISTRY_TOKEN: sdkRegistryToken, RUST_LOG: "info", CARGO_TERM_COLOR: "always" },
  workingDirectory: "",
  serviceDependencies: ["postgres"],
  retry: {
    maxRetries: 2,
    flakeSignatures: reordered ? ["timed out", "connection reset"] : ["connection reset", "timed out"],
  },
  cachePaths: reordered ? ["target", "target/debug"] : ["target/debug", "target"],
  isolation: {
    profile: "linux-medium",
    networkAccess: "services-only",
    cpuMillis: 2000,
    memoryBytes: 4_294_967_296n,
    processLimit: 256,
  },
  triggers: reordered
    ? [{ kind: "push" }, { kind: "cron", cronExpression: "0 3 * * 1" }, { kind: "manual" }]
    : [{ kind: "manual" }, { kind: "cron", cronExpression: "0 3 * * 1" }, { kind: "push" }],
  supersedeOlderRuns: true,
  targetEnvironment: {
    ociImageDigest: sha256Digest("1"),
    platform: { os: "linux", arch: "amd64" },
  },
  determinismClass: "deterministic",
});

const sdkLintInput = () => ({
  name: "lint",
  command: "cargo",
  args: ["clippy", "--", "-D", "warnings"],
  class: "advisory",
  timeoutSeconds: 900,
  env: {},
  workingDirectory: "crates/core",
  serviceDependencies: [],
  retry: { maxRetries: 0, flakeSignatures: [] },
  cachePaths: [],
  isolation: {
    profile: "",
    networkAccess: "none",
    cpuMillis: 0,
    memoryBytes: 0n,
    processLimit: 0,
  },
  triggers: [{ kind: "push" }],
  supersedeOlderRuns: false,
  targetEnvironment: {
    ociImageDigest: sha256Digest("2"),
    platform: { os: "linux", arch: "arm64" },
  },
  determinismClass: "deterministic",
});
const sdkLintCheck = () => defineCheck(sdkLintInput());

const sdkDocsCheck = defineCheck({
  name: "build",
  command: "npm",
  args: ["run", "docs"],
  class: "informational",
  timeoutSeconds: 600,
  env: {},
  workingDirectory: "docs",
  serviceDependencies: [],
  retry: { maxRetries: 0, flakeSignatures: [] },
  cachePaths: [],
  isolation: {
    profile: "",
    networkAccess: "full",
    cpuMillis: 0,
    memoryBytes: 0n,
    processLimit: 0,
  },
  triggers: [{ kind: "manual" }],
  supersedeOlderRuns: true,
  targetEnvironment: {
    ociImageDigest: sha256Digest("3"),
    platform: { os: "linux", arch: "amd64" },
  },
  determinismClass: "nondeterministic",
});

const sdkTestJob = (reordered = false) => job({
  matrix: matrix(reordered
    ? { toolchain: ["stable"], target: ["x86_64-unknown-linux-gnu"] }
    : { target: ["x86_64-unknown-linux-gnu"], toolchain: ["stable"] }),
  name: () => "test-linux",
  checks: () => reordered
    ? [sdkLintCheck(), sdkUnitCheck(true)]
    : [sdkUnitCheck(), sdkLintCheck()],
});

const sdkDocsJob = job({ name: "docs", checks: [sdkDocsCheck] });
const sdkPostgres = (reordered = false) => defineService({
  name: "postgres",
  image: "postgres:16",
  ports: reordered ? [5432, 5433] : [5433, 5432],
  env: reordered
    ? { POSTGRES_PASSWORD: sdkDbPassword, POSTGRES_DB: "treadle" }
    : { POSTGRES_DB: "treadle", POSTGRES_PASSWORD: sdkDbPassword },
  readiness: { command: "pg_isready", args: ["-U", "treadle"] },
  ociImageDigest: sha256Digest("4"),
});

const sdkEmission = emitPipeline(definePipeline({
  name: "heddle-ci",
  jobs: [sdkTestJob(), sdkDocsJob],
  services: [sdkPostgres()],
  secretRefs: [sdkRegistryToken, sdkDbPassword],
}));
const sdkEmissionAgain = emitPipeline(definePipeline({
  name: "heddle-ci",
  jobs: [sdkTestJob(), sdkDocsJob],
  services: [sdkPostgres()],
  secretRefs: [sdkRegistryToken, sdkDbPassword],
}));
const sdkReorderedEmission = emitPipeline(definePipeline({
  name: "heddle-ci",
  jobs: [sdkDocsJob, sdkTestJob(true)],
  services: [sdkPostgres(true)],
  secretRefs: [sdkDbPassword, sdkRegistryToken],
}));

for (const emission of [sdkEmission, sdkEmissionAgain, sdkReorderedEmission]) {
  assert.equal(Buffer.from(emission.canonicalBytes).toString("hex"), canonicalHex);
  assert.equal(emission.definitionDigest, blake3Hex);
  assert.deepEqual(
    fromBinary(TreadleDefinitionSchema, emission.canonicalBytes),
    emission.definition,
  );
  assert.equal(emission.lockFile.path, "treadle.lock.json");
  assert.deepEqual(JSON.parse(emission.lockFile.contents), {
    format_version: 1,
    definition_digest: blake3Hex,
  });
}

const matrixCheck = (runtime, arch) => defineCheck({
  name: "unit",
  command: "npm",
  args: ["test", "--", "--runtime", runtime, "--arch", arch],
  class: "required",
  timeoutSeconds: 300,
  env: { RUNTIME: runtime, ARCH: arch },
  workingDirectory: "",
  serviceDependencies: [],
  retry: { maxRetries: 0, flakeSignatures: [] },
  cachePaths: [],
  isolation: {
    profile: "",
    networkAccess: "none",
    cpuMillis: 0,
    memoryBytes: 0n,
    processLimit: 0,
  },
  triggers: [{ kind: "push" }],
  supersedeOlderRuns: true,
  targetEnvironment: {
    ociImageDigest: sha256Digest("5"),
    platform: { os: "linux", arch },
  },
  determinismClass: "deterministic",
});
const fanout = matrix({ runtime: ["node22", "node20"], arch: ["arm64", "amd64"] });
const matrixEmission = emitPipeline(definePipeline({
  name: "matrix-ci",
  jobs: [job({
    matrix: fanout,
    name: ({ runtime, arch }) => `test-${runtime}-${arch}`,
    checks: ({ runtime, arch }) => [matrixCheck(runtime, arch)],
  })],
  services: [],
  secretRefs: [],
}));
const reorderedFanout = matrix({ arch: ["amd64", "arm64"], runtime: ["node20", "node22"] });
const reorderedMatrixEmission = emitPipeline(definePipeline({
  name: "matrix-ci",
  jobs: [job({
    matrix: reorderedFanout,
    name: ({ runtime, arch }) => `test-${runtime}-${arch}`,
    checks: ({ runtime, arch }) => [matrixCheck(runtime, arch)],
  })],
  services: [],
  secretRefs: [],
}));
assert.deepEqual(reorderedMatrixEmission.canonicalBytes, matrixEmission.canonicalBytes);
assert.equal(reorderedMatrixEmission.definitionDigest, matrixEmission.definitionDigest);
assert.deepEqual(
  matrixEmission.definition.jobs.map((jobMessage) => `${jobMessage.name}/${jobMessage.checks[0].name}`),
  [
    "test-node20-amd64/unit",
    "test-node20-arm64/unit",
    "test-node22-amd64/unit",
    "test-node22-arm64/unit",
  ],
);
assert.equal(matrixEmission.definition.jobs.length, 4);
for (const jobMessage of matrixEmission.definition.jobs) {
  assert.equal(jobMessage.matrix.length, 2);
  assert.ok(allStrings(jobMessage).every((value) => !value.includes("${") && !value.includes("{{")));
}

const unresolved = defineCheck({
  ...sdkLintInput(),
  args: ["${{ matrix.toolchain }}"],
});
assert.throws(
  () => emitPipeline(definePipeline({
    name: "unresolved-ci",
    jobs: [job({ name: "test", checks: [unresolved] })],
    services: [],
    secretRefs: [],
  })),
  /looks unresolved/,
);

const missingTargetEnvironment = structuredClone(definition);
missingTargetEnvironment.jobs[0].checks[0].targetEnvironment = undefined;
assert.throws(
  () => canonicalTreadleDefinitionBytes(missingTargetEnvironment),
  /omits targetEnvironment/,
);

const missingPlatform = structuredClone(definition);
missingPlatform.jobs[0].checks[0].targetEnvironment.platform = undefined;
assert.throws(
  () => canonicalTreadleDefinitionBytes(missingPlatform),
  /omits targetEnvironment\.platform/,
);

const reorderedDefinition = structuredClone(definition);
reorderedDefinition.jobs.reverse();
reorderedDefinition.services.reverse();
reorderedDefinition.secretRefs.reverse();
for (const job of reorderedDefinition.jobs) {
  job.matrix.reverse();
  job.checks.reverse();
  for (const check of job.checks) {
    check.env.reverse();
    check.serviceDependencies.reverse();
    check.retry.flakeSignatures.reverse();
    check.cachePaths.reverse();
    check.triggers.reverse();
  }
}
for (const service of reorderedDefinition.services) {
  service.ports.reverse();
  service.env.reverse();
}
assert.equal(
  Buffer.from(canonicalTreadleDefinitionBytes(reorderedDefinition)).toString("hex"),
  canonicalHex,
);

if (process.argv.includes("--print")) {
  process.stdout.write(`${JSON.stringify({
    format: "heddle-treadle-definition-v1",
    producer: "@heddleco/api TypeScript canonicalTreadleDefinitionBytes",
    canonical_hex: canonicalHex,
    blake3_hex: blake3Hex,
  }, null, 2)}\n`);
} else {
  const fixture = JSON.parse(
    readFileSync("tests/fixtures/treadle-definition-v1.json", "utf8"),
  );
  if (canonicalHex !== fixture.canonical_hex) {
    throw new Error("TypeScript canonical treadle bytes differ from the shared golden fixture");
  }
  if (blake3Hex !== fixture.blake3_hex) {
    throw new Error("TypeScript treadle BLAKE3 differs from the shared golden fixture");
  }
  process.stdout.write(`treadle TS canonical bytes: ${canonicalHex.length / 2} bytes\n`);
  process.stdout.write(`treadle TS blake3: ${blake3Hex}\n`);
  process.stdout.write(
    "treadle TS negative cases: missing target environment/platform rejected; reordered input matched\n",
  );
  process.stdout.write(
    "treadle authoring SDK: golden/digest/lock deterministic; reordered authoring matched; 4 matrix checks concrete; round-trip matched\n",
  );
}

function allStrings(value) {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(allStrings);
  if (value !== null && typeof value === "object") return Object.values(value).flatMap(allStrings);
  return [];
}
