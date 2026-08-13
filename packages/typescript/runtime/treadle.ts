import { create, toBinary } from "@bufbuild/protobuf";
import { blake3 } from "@noble/hashes/blake3.js";
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
  type TreadleCheck,
  type TreadleDefinition,
  type TreadleEnvEntry,
  type TreadleServiceContainer,
  type TreadleTrigger,
} from "./treadle_pb.js";

export const TREADLE_DEFINITION_FORMAT_VERSION = 1;

export class TreadleDefinitionError extends Error {
  override name = "TreadleDefinitionError";
}

/** Validate, normalize, and protobuf-encode a v1 treadle definition canonically. */
export function canonicalTreadleDefinitionBytes(
  definition: TreadleDefinition,
): Uint8Array {
  return toBinary(TreadleDefinitionSchema, canonicalDefinition(definition), {
    writeUnknownFields: false,
  });
}

/** BLAKE3 content address of the canonical protobuf bytes. */
export function treadleDefinitionBlake3(definition: TreadleDefinition): Uint8Array {
  return blake3(canonicalTreadleDefinitionBytes(definition));
}

function canonicalDefinition(definition: TreadleDefinition): TreadleDefinition {
  if (definition.formatVersion !== TREADLE_DEFINITION_FORMAT_VERSION) {
    throw new TreadleDefinitionError(
      `unsupported treadle definition format version ${definition.formatVersion}; ` +
        `migrate to version ${TREADLE_DEFINITION_FORMAT_VERSION} before reading`,
    );
  }
  nonEmpty("pipeline name", definition.name);

  const secretRefs = definition.secretRefs
    .map((secret) => {
      identifier("secret", secret.name);
      noNul("secret provider", secret.provider);
      if (![TreadleSecretTier.STANDARD, TreadleSecretTier.TRUSTED_RUNNER_ONLY].includes(secret.tier)) {
        throw new TreadleDefinitionError(
          `secret ${JSON.stringify(secret.name)} has an invalid tier`,
        );
      }
      return create(TreadleSecretRefSchema, secret);
    })
    .sort((left, right) => byteCompare(left.name, right.name));
  uniqueNames("secret declaration", secretRefs);
  const secretNames = new Set(secretRefs.map((secret) => secret.name));

  const services = definition.services
    .map((service) => canonicalService(service, secretNames))
    .sort((left, right) => byteCompare(left.name, right.name));
  uniqueNames("service", services);
  const serviceNames = new Set(services.map((service) => service.name));

  const jobs = definition.jobs
    .map((job) => {
      identifier("job", job.name);
      const matrix = job.matrix
        .map((binding) => {
          identifier("matrix dimension", binding.name);
          noNul("matrix value", binding.value);
          if (binding.value.includes("${") || binding.value.includes("{{")) {
            throw new TreadleDefinitionError(
              `job ${JSON.stringify(job.name)} matrix value ${JSON.stringify(binding.value)} looks unresolved`,
            );
          }
          return create(TreadleMatrixValueSchema, binding);
        })
        .sort((left, right) => byteCompare(left.name, right.name));
      uniqueNames("matrix dimension", matrix);

      const checks = job.checks
        .map((check) => canonicalCheck(check, serviceNames, secretNames))
        .sort((left, right) => byteCompare(left.name, right.name));
      uniqueNames("check", checks);
      if (checks.length === 0) {
        throw new TreadleDefinitionError(`job ${JSON.stringify(job.name)} has no checks`);
      }
      return create(TreadleJobSchema, { name: job.name, matrix, checks });
    })
    .sort((left, right) => byteCompare(left.name, right.name));
  if (jobs.length === 0) {
    throw new TreadleDefinitionError("pipeline has no jobs");
  }
  uniqueNames("job", jobs);

  return create(TreadleDefinitionSchema, {
    formatVersion: TREADLE_DEFINITION_FORMAT_VERSION,
    name: definition.name,
    jobs,
    services,
    secretRefs,
  });
}

function canonicalCheck(
  check: TreadleCheck,
  serviceNames: Set<string>,
  secretNames: Set<string>,
): TreadleCheck {
  identifier("check", check.name);
  nonEmpty("check command", check.command);
  check.args.forEach((arg) => noNul("check argument", arg));
  if (![TreadleCheckClass.REQUIRED, TreadleCheckClass.ADVISORY, TreadleCheckClass.INFORMATIONAL].includes(check.class)) {
    throw new TreadleDefinitionError(`check ${JSON.stringify(check.name)} has an invalid class`);
  }
  if (![
    TreadleDeterminismClass.DETERMINISTIC,
    TreadleDeterminismClass.NONDETERMINISTIC,
  ].includes(check.determinismClass)) {
    throw new TreadleDefinitionError(
      `check ${JSON.stringify(check.name)} has an invalid determinismClass`,
    );
  }
  positiveUint32("timeoutSeconds", check.timeoutSeconds);
  relativePath("workingDirectory", check.workingDirectory, true);

  if (check.targetEnvironment === undefined) {
    throw new TreadleDefinitionError(
      `check ${JSON.stringify(check.name)} omits targetEnvironment`,
    );
  }
  ociImageDigest("target environment OCI image digest", check.targetEnvironment.ociImageDigest);
  if (check.targetEnvironment.platform === undefined) {
    throw new TreadleDefinitionError(
      `check ${JSON.stringify(check.name)} omits targetEnvironment.platform`,
    );
  }
  platformValue("target platform os", check.targetEnvironment.platform.os);
  platformValue("target platform arch", check.targetEnvironment.platform.arch);
  const targetEnvironment = create(TreadleTargetEnvironmentSchema, {
    ociImageDigest: check.targetEnvironment.ociImageDigest,
    platform: create(TreadlePlatformSchema, check.targetEnvironment.platform),
  });

  const env = canonicalEnv(check.env, secretNames);
  const serviceDependencies = sortedUnique("service dependency", check.serviceDependencies);
  for (const dependency of serviceDependencies) {
    if (!serviceNames.has(dependency)) {
      throw new TreadleDefinitionError(
        `check ${JSON.stringify(check.name)} references undeclared service ${JSON.stringify(dependency)}`,
      );
    }
  }

  if (check.retry === undefined) {
    throw new TreadleDefinitionError(`check ${JSON.stringify(check.name)} omits retry`);
  }
  const flakeSignatures = sortedUnique("flake signature", check.retry.flakeSignatures);
  flakeSignatures.forEach((signature) => nonEmpty("flake signature", signature));
  const retry = create(TreadleRetrySchema, {
    maxRetries: uint32("maxRetries", check.retry.maxRetries),
    flakeSignatures,
  });

  const cachePaths = sortedUnique("cache path", check.cachePaths);
  cachePaths.forEach((path) => relativePath("cache path", path, false));

  if (check.isolation === undefined) {
    throw new TreadleDefinitionError(`check ${JSON.stringify(check.name)} omits isolation`);
  }
  noNul("isolation profile", check.isolation.profile);
  const cpuMillis = uint32("cpuMillis", check.isolation.cpuMillis);
  const processLimit = uint32("processLimit", check.isolation.processLimit);
  if (
    typeof check.isolation.memoryBytes !== "bigint" ||
    check.isolation.memoryBytes < 0n ||
    check.isolation.memoryBytes > 0xffff_ffff_ffff_ffffn
  ) {
    throw new TreadleDefinitionError("memoryBytes must be a uint64");
  }
  if (![
    TreadleNetworkAccess.UNSPECIFIED,
    TreadleNetworkAccess.NONE,
    TreadleNetworkAccess.SERVICES_ONLY,
    TreadleNetworkAccess.FULL,
  ].includes(check.isolation.networkAccess)) {
    throw new TreadleDefinitionError(
      `check ${JSON.stringify(check.name)} has invalid networkAccess`,
    );
  }
  const isolation = create(TreadleIsolationHintsSchema, {
    ...check.isolation,
    cpuMillis,
    processLimit,
  });

  const triggers = check.triggers
    .map((trigger) => canonicalTrigger(check.name, trigger))
    .sort((left, right) => left.kind - right.kind || byteCompare(left.cronExpression, right.cronExpression));
  if (triggers.length === 0) {
    throw new TreadleDefinitionError(`check ${JSON.stringify(check.name)} has no triggers`);
  }
  const triggerKeys = triggers.map((trigger) => `${trigger.kind}\u0000${trigger.cronExpression}`);
  if (new Set(triggerKeys).size !== triggerKeys.length) {
    throw new TreadleDefinitionError(`check ${JSON.stringify(check.name)} has a duplicate trigger`);
  }

  return create(TreadleCheckSchema, {
    name: check.name,
    command: check.command,
    args: [...check.args],
    class: check.class,
    timeoutSeconds: check.timeoutSeconds,
    env,
    workingDirectory: check.workingDirectory,
    serviceDependencies,
    retry,
    cachePaths,
    isolation,
    triggers,
    supersedeOlderRuns: check.supersedeOlderRuns,
    targetEnvironment,
    determinismClass: check.determinismClass,
  });
}

function canonicalService(
  service: TreadleServiceContainer,
  secretNames: Set<string>,
): TreadleServiceContainer {
  identifier("service", service.name);
  nonEmpty("service image", service.image);
  ociImageDigest("service OCI image digest", service.ociImageDigest);
  const ports = [...service.ports].sort((left, right) => left - right);
  ports.forEach((port) => {
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new TreadleDefinitionError(`service ${JSON.stringify(service.name)} has invalid port ${port}`);
    }
  });
  if (new Set(ports).size !== ports.length) {
    throw new TreadleDefinitionError(`service ${JSON.stringify(service.name)} has a duplicate port`);
  }
  let readiness;
  if (service.readiness !== undefined) {
    nonEmpty("service readiness command", service.readiness.command);
    service.readiness.args.forEach((arg) => noNul("service readiness argument", arg));
    readiness = create(TreadleArgvSchema, {
      command: service.readiness.command,
      args: [...service.readiness.args],
    });
  }
  return create(TreadleServiceContainerSchema, {
    name: service.name,
    image: service.image,
    ports,
    env: canonicalEnv(service.env, secretNames),
    readiness,
    ociImageDigest: service.ociImageDigest,
  });
}

function canonicalEnv(env: TreadleEnvEntry[], secretNames: Set<string>): TreadleEnvEntry[] {
  const result = env
    .map((entry) => {
      nonEmpty("environment name", entry.name);
      if (entry.source.case === "literalValue") {
        noNul("environment literal", entry.source.value);
      } else if (entry.source.case === "secretRef") {
        if (!secretNames.has(entry.source.value)) {
          throw new TreadleDefinitionError(
            `environment references undeclared secret ${JSON.stringify(entry.source.value)}`,
          );
        }
      } else {
        throw new TreadleDefinitionError(
          `environment ${JSON.stringify(entry.name)} has no source`,
        );
      }
      return create(TreadleEnvEntrySchema, entry);
    })
    .sort((left, right) => byteCompare(left.name, right.name));
  uniqueNames("environment entry", result);
  return result;
}

function canonicalTrigger(checkName: string, trigger: TreadleTrigger): TreadleTrigger {
  if (
    (trigger.kind === TreadleTriggerKind.PUSH || trigger.kind === TreadleTriggerKind.MANUAL) &&
    trigger.cronExpression === ""
  ) {
    return create(TreadleTriggerSchema, trigger);
  }
  if (trigger.kind === TreadleTriggerKind.CRON && validCron(trigger.cronExpression)) {
    return create(TreadleTriggerSchema, trigger);
  }
  throw new TreadleDefinitionError(`check ${JSON.stringify(checkName)} has an invalid trigger`);
}

function uniqueNames(kind: string, values: Array<{ name: string }>): void {
  if (new Set(values.map((value) => value.name)).size !== values.length) {
    throw new TreadleDefinitionError(`duplicate ${kind} name`);
  }
}

function sortedUnique(kind: string, values: string[]): string[] {
  const result = [...values].sort(byteCompare);
  if (new Set(result).size !== result.length) {
    throw new TreadleDefinitionError(`duplicate ${kind}`);
  }
  return result;
}

function identifier(kind: string, value: string): void {
  if (
    value.length === 0 ||
    ![...value].every((character) =>
      (character >= "a" && character <= "z") ||
      (character >= "0" && character <= "9") ||
      "._:-".includes(character),
    )
  ) {
    throw new TreadleDefinitionError(
      `${kind} name ${JSON.stringify(value)} must match [a-z0-9._:-]+`,
    );
  }
}

function nonEmpty(kind: string, value: string): void {
  if (value.length === 0) throw new TreadleDefinitionError(`${kind} must not be empty`);
  noNul(kind, value);
}

function noNul(kind: string, value: string): void {
  if (value.includes("\u0000")) {
    throw new TreadleDefinitionError(`${kind} must not contain NUL`);
  }
}

function ociImageDigest(kind: string, value: string): void {
  if (!/^sha256:[0-9a-f]{64}$/.test(value)) {
    throw new TreadleDefinitionError(
      `${kind} must be sha256: followed by 64 lowercase hexadecimal digits`,
    );
  }
}

function platformValue(kind: string, value: string): void {
  if (!/^[a-z0-9]+$/.test(value)) {
    throw new TreadleDefinitionError(`${kind} must match [a-z0-9]+`);
  }
}

function positiveUint32(kind: string, value: number): void {
  if (uint32(kind, value) === 0) {
    throw new TreadleDefinitionError(`${kind} must be a positive uint32`);
  }
}

function uint32(kind: string, value: number): number {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new TreadleDefinitionError(`${kind} must be a uint32`);
  }
  return value;
}

function relativePath(kind: string, value: string, allowEmpty: boolean): void {
  if (value.length === 0 && allowEmpty) return;
  const segments = value.split("/");
  if (
    value.length === 0 ||
    value.startsWith("/") ||
    value.includes("\\") ||
    /^[A-Za-z]:/.test(value) ||
    segments.some((segment) => segment === "" || segment === "." || segment === "..")
  ) {
    throw new TreadleDefinitionError(
      `${kind} ${JSON.stringify(value)} must be a normalized repository-relative path`,
    );
  }
  noNul(kind, value);
}

function validCron(value: string): boolean {
  const fields = value.split(" ");
  return fields.length === 5 && fields.every((field) =>
    field.length > 0 && [...field].every((character) =>
      (character >= "0" && character <= "9") || "*,-/".includes(character),
    ),
  );
}

const utf8 = new TextEncoder();

function byteCompare(left: string, right: string): number {
  const leftBytes = utf8.encode(left);
  const rightBytes = utf8.encode(right);
  const length = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < length; index += 1) {
    const difference = leftBytes[index]! - rightBytes[index]!;
    if (difference !== 0) return difference;
  }
  return leftBytes.length - rightBytes.length;
}
