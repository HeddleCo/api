import { readFileSync } from "node:fs";
import { create } from "@bufbuild/protobuf";
import {
  TreadleArgvSchema,
  TreadleCheckClass,
  TreadleCheckSchema,
  TreadleDefinitionSchema,
  TreadleEnvEntrySchema,
  TreadleIsolationHintsSchema,
  TreadleJobSchema,
  TreadleMatrixValueSchema,
  TreadleNetworkAccess,
  TreadleRetrySchema,
  TreadleSecretRefSchema,
  TreadleServiceContainerSchema,
  TreadleTriggerKind,
  TreadleTriggerSchema,
} from "../packages/typescript/dist/treadle_pb.js";
import {
  canonicalTreadleDefinitionBytes,
  treadleDefinitionBlake3,
} from "../packages/typescript/dist/treadle.js";

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

// Intentionally unordered: canonicalization, rather than fixture construction,
// owns every set-like ordering decision.
const definition = create(TreadleDefinitionSchema, {
  formatVersion: 1,
  name: "heddle-ci",
  secretRefs: [
    create(TreadleSecretRefSchema, { name: "registry-token", provider: "vault" }),
    create(TreadleSecretRefSchema, { name: "db-password" }),
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
        }),
      ],
    }),
  ],
});

const canonicalHex = Buffer.from(canonicalTreadleDefinitionBytes(definition)).toString("hex");
const blake3Hex = Buffer.from(treadleDefinitionBlake3(definition)).toString("hex");

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
}
