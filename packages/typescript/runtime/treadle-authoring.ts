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
  type TreadleDefinition,
  type TreadleJob,
} from "./treadle_pb.js";
import {
  TREADLE_DEFINITION_FORMAT_VERSION,
  TreadleDefinitionError,
  canonicalTreadleDefinitionBytes,
  treadleDefinitionBlake3,
} from "./treadle.js";

export type CheckClass = "required" | "advisory" | "informational";
export type DeterminismClass = "deterministic" | "nondeterministic";
export type NetworkAccess = "unspecified" | "none" | "services-only" | "full";
export type SecretTier = "standard" | "trusted-runner-only";

export interface SecretReference {
  readonly name: string;
  readonly provider: string;
  readonly tier: SecretTier;
}

export interface SecretReferenceInput {
  readonly name: string;
  readonly provider?: string;
  readonly tier: SecretTier;
}

export type Environment = Readonly<Record<string, string | SecretReference>>;

export interface CheckInput {
  readonly name: string;
  readonly command: string;
  readonly args: readonly string[];
  readonly class: CheckClass;
  readonly timeoutSeconds: number;
  readonly env: Environment;
  readonly workingDirectory: string;
  readonly serviceDependencies: readonly string[];
  readonly retry: {
    readonly maxRetries: number;
    readonly flakeSignatures: readonly string[];
  };
  readonly cachePaths: readonly string[];
  readonly isolation: {
    readonly profile: string;
    readonly networkAccess: NetworkAccess;
    readonly cpuMillis: number;
    readonly memoryBytes: bigint;
    readonly processLimit: number;
  };
  readonly triggers: readonly (
    | { readonly kind: "push" | "manual" }
    | { readonly kind: "cron"; readonly cronExpression: string }
  )[];
  readonly supersedeOlderRuns: boolean;
  readonly targetEnvironment: {
    readonly ociImageDigest: string;
    readonly platform: {
      readonly os: string;
      readonly arch: string;
    };
  };
  readonly determinismClass: DeterminismClass;
}

export interface ServiceInput {
  readonly name: string;
  readonly image: string;
  readonly ports: readonly number[];
  readonly env: Environment;
  readonly readiness?: {
    readonly command: string;
    readonly args: readonly string[];
  };
  readonly ociImageDigest: string;
}

export interface MatrixDefinition<
  Axes extends Readonly<Record<string, readonly string[]>>,
> {
  readonly axes: Axes;
}

export type MatrixValues<
  Axes extends Readonly<Record<string, readonly string[]>>,
> = {
  readonly [Key in keyof Axes]: Axes[Key][number];
};

export interface PipelineInput {
  readonly name: string;
  readonly jobs: readonly JobDefinition[];
  readonly services: readonly ServiceDefinition[];
  readonly secretRefs: readonly SecretReference[];
}

declare const checkDefinitionBrand: unique symbol;
declare const serviceDefinitionBrand: unique symbol;
declare const jobDefinitionBrand: unique symbol;
declare const pipelineDefinitionBrand: unique symbol;

/** Opaque reusable check returned by defineCheck(). */
export interface CheckDefinition {
  readonly [checkDefinitionBrand]: true;
}

/** Opaque reusable service returned by defineService(). */
export interface ServiceDefinition {
  readonly [serviceDefinitionBrand]: true;
}

/** Opaque reusable static or matrix job returned by job(). */
export interface JobDefinition {
  readonly [jobDefinitionBrand]: true;
}

/** Opaque authored pipeline returned by definePipeline(). */
export interface PipelineDefinition {
  readonly [pipelineDefinitionBrand]: true;
}

export interface TreadleLock {
  readonly format_version: typeof TREADLE_DEFINITION_FORMAT_VERSION;
  /** Lowercase hexadecimal BLAKE3 of the canonical protobuf bytes. */
  readonly definition_digest: string;
}

export interface TreadleEmission {
  /** Canonically ordered message decoded from canonicalBytes. */
  readonly definition: TreadleDefinition;
  readonly canonicalBytes: Uint8Array;
  /** Lowercase hexadecimal BLAKE3 of canonicalBytes. */
  readonly definitionDigest: string;
  readonly lockFile: {
    readonly path: "treadle.lock.json";
    readonly contents: string;
  };
}

interface ExpandedJob {
  readonly name: string;
  readonly matrix: Readonly<Record<string, string>>;
  readonly checks: readonly CheckDefinition[];
}

/** Declare a names-only secret grant that can also be used as an env value. */
export function secretRef(input: SecretReferenceInput): SecretReference {
  return Object.freeze({
    name: input.name,
    provider: input.provider ?? "",
    tier: input.tier,
  });
}

/** Declare one complete, argv-only signable check. */
export function defineCheck(input: CheckInput): CheckDefinition {
  const definition = Object.freeze({}) as CheckDefinition;
  checkInputs.set(definition, input);
  return definition;
}

/** Declare one pipeline-wide service container. */
export function defineService(input: ServiceInput): ServiceDefinition {
  const definition = Object.freeze({}) as ServiceDefinition;
  serviceInputs.set(definition, input);
  return definition;
}

/** Declare author-time matrix axes. Every axis must have unique values. */
export function matrix<
  const Axes extends Readonly<Record<string, readonly string[]>>,
>(axes: Axes): MatrixDefinition<Axes> {
  const names = Object.keys(axes);
  if (names.length === 0) {
    throw new TreadleDefinitionError("matrix has no axes");
  }
  for (const name of names) {
    const values = axes[name]!;
    if (values.length === 0) {
      throw new TreadleDefinitionError(`matrix axis ${JSON.stringify(name)} has no values`);
    }
    if (new Set(values).size !== values.length) {
      throw new TreadleDefinitionError(
        `matrix axis ${JSON.stringify(name)} has a duplicate value`,
      );
    }
    for (const value of values) rejectUnresolved(`matrix axis ${JSON.stringify(name)}`, value);
  }
  return Object.freeze({ axes });
}

export function job(input: {
  readonly name: string;
  readonly checks: readonly CheckDefinition[];
}): JobDefinition;
export function job<
  const Axes extends Readonly<Record<string, readonly string[]>>,
>(input: {
  readonly name: (values: MatrixValues<Axes>) => string;
  readonly matrix: MatrixDefinition<Axes>;
  readonly checks: (values: MatrixValues<Axes>) => readonly CheckDefinition[];
}): JobDefinition;
/** Declare a reusable static job or an author-time-expanded matrix job. */
export function job<
  Axes extends Readonly<Record<string, readonly string[]>>,
>(input: {
  readonly name: string | ((values: MatrixValues<Axes>) => string);
  readonly matrix?: MatrixDefinition<Axes>;
  readonly checks:
    | readonly CheckDefinition[]
    | ((values: MatrixValues<Axes>) => readonly CheckDefinition[]);
}): JobDefinition {
  if (input.matrix === undefined) {
    if (typeof input.name !== "string" || typeof input.checks === "function") {
      throw new TreadleDefinitionError("static job requires a string name and check array");
    }
    return newJob(() => [{
      name: input.name as string,
      matrix: {},
      checks: input.checks as readonly CheckDefinition[],
    }]);
  }
  if (typeof input.name !== "function" || typeof input.checks !== "function") {
    throw new TreadleDefinitionError("matrix job requires name and checks functions");
  }
  const name = input.name;
  const checks = input.checks;
  const axes = input.matrix.axes;
  return newJob(() => expandMatrix(axes).map((values) => ({
    name: name(values as MatrixValues<Axes>),
    matrix: values,
    checks: checks(values as MatrixValues<Axes>),
  })));
}

/** Compose reusable jobs, services, and secret declarations into a pipeline. */
export function definePipeline(input: PipelineInput): PipelineDefinition {
  const definition = Object.freeze({}) as PipelineDefinition;
  pipelineInputs.set(definition, input);
  return definition;
}

/** Lower a pipeline to canonical protobuf bytes and its deterministic lock artifact. */
export function emitPipeline(pipeline: PipelineDefinition): TreadleEmission {
  const input = requireDefined(pipelineInputs, pipeline, "pipeline", "definePipeline");
  const definition = create(TreadleDefinitionSchema, {
    formatVersion: TREADLE_DEFINITION_FORMAT_VERSION,
    name: input.name,
    jobs: input.jobs.flatMap((definition) =>
      requireDefined(jobExpanders, definition, "job", "job")().map(buildJob),
    ),
    services: input.services.map(buildService),
    secretRefs: input.secretRefs.map((reference) =>
      create(TreadleSecretRefSchema, {
        name: reference.name,
        provider: reference.provider,
        tier: secretTiers[reference.tier],
      }),
    ),
  });
  rejectUnresolvedDefinition(definition);

  const canonicalBytes = canonicalTreadleDefinitionBytes(definition);
  const canonicalDefinition = fromBinary(TreadleDefinitionSchema, canonicalBytes);
  const definitionDigest = hex(treadleDefinitionBlake3(canonicalDefinition));
  const lock: TreadleLock = {
    format_version: TREADLE_DEFINITION_FORMAT_VERSION,
    definition_digest: definitionDigest,
  };

  return Object.freeze({
    definition: canonicalDefinition,
    canonicalBytes,
    definitionDigest,
    lockFile: Object.freeze({
      path: "treadle.lock.json" as const,
      contents: `${JSON.stringify(lock, null, 2)}\n`,
    }),
  });
}

function buildJob(job: ExpandedJob): TreadleJob {
  return create(TreadleJobSchema, {
    name: job.name,
    matrix: Object.entries(job.matrix).map(([name, value]) =>
      create(TreadleMatrixValueSchema, { name, value }),
    ),
    checks: job.checks.map((definition) => {
      const input = requireDefined(checkInputs, definition, "check", "defineCheck");
      return create(TreadleCheckSchema, {
        name: input.name,
        command: input.command,
        args: [...input.args],
        class: checkClasses[input.class],
        timeoutSeconds: input.timeoutSeconds,
        env: buildEnv(input.env),
        workingDirectory: input.workingDirectory,
        serviceDependencies: [...input.serviceDependencies],
        retry: create(TreadleRetrySchema, {
          maxRetries: input.retry.maxRetries,
          flakeSignatures: [...input.retry.flakeSignatures],
        }),
        cachePaths: [...input.cachePaths],
        isolation: create(TreadleIsolationHintsSchema, {
          profile: input.isolation.profile,
          networkAccess: networkAccessValues[input.isolation.networkAccess],
          cpuMillis: input.isolation.cpuMillis,
          memoryBytes: input.isolation.memoryBytes,
          processLimit: input.isolation.processLimit,
        }),
        triggers: input.triggers.map((trigger) => create(TreadleTriggerSchema, {
          kind: triggerKinds[trigger.kind],
          cronExpression: trigger.kind === "cron" ? trigger.cronExpression : "",
        })),
        supersedeOlderRuns: input.supersedeOlderRuns,
        targetEnvironment: create(TreadleTargetEnvironmentSchema, {
          ociImageDigest: input.targetEnvironment.ociImageDigest,
          platform: create(TreadlePlatformSchema, input.targetEnvironment.platform),
        }),
        determinismClass: determinismClasses[input.determinismClass],
      });
    }),
  });
}

function buildService(definition: ServiceDefinition) {
  const input = requireDefined(serviceInputs, definition, "service", "defineService");
  return create(TreadleServiceContainerSchema, {
    name: input.name,
    image: input.image,
    ports: [...input.ports],
    env: buildEnv(input.env),
    readiness: input.readiness === undefined ? undefined : create(TreadleArgvSchema, {
      command: input.readiness.command,
      args: [...input.readiness.args],
    }),
    ociImageDigest: input.ociImageDigest,
  });
}

function newJob(expand: () => readonly ExpandedJob[]): JobDefinition {
  const definition = Object.freeze({}) as JobDefinition;
  jobExpanders.set(definition, expand);
  return definition;
}

function requireDefined<Key extends object, Value>(
  definitions: WeakMap<Key, Value>,
  key: Key,
  kind: string,
  factory: string,
): Value {
  const value = definitions.get(key);
  if (value === undefined) {
    throw new TreadleDefinitionError(`${kind} must be created by ${factory}()`);
  }
  return value;
}

function buildEnv(environment: Environment) {
  return Object.entries(environment).map(([name, value]) =>
    create(TreadleEnvEntrySchema, {
      name,
      source: typeof value === "string"
        ? { case: "literalValue", value }
        : { case: "secretRef", value: value.name },
    }),
  );
}

function expandMatrix(
  axes: Readonly<Record<string, readonly string[]>>,
): Readonly<Record<string, string>>[] {
  let coordinates: Readonly<Record<string, string>>[] = [{}];
  for (const name of Object.keys(axes).sort()) {
    coordinates = coordinates.flatMap((coordinate) =>
      axes[name]!.map((value) => ({ ...coordinate, [name]: value })),
    );
  }
  return coordinates;
}

function rejectUnresolvedDefinition(definition: TreadleDefinition): void {
  rejectUnresolved("pipeline name", definition.name);
  for (const reference of definition.secretRefs) {
    rejectUnresolved("secret name", reference.name);
    rejectUnresolved("secret provider", reference.provider);
  }
  for (const service of definition.services) {
    rejectUnresolved("service name", service.name);
    rejectUnresolved("service image", service.image);
    rejectUnresolved("service OCI digest", service.ociImageDigest);
    rejectUnresolvedEnv(service.env);
    if (service.readiness !== undefined) {
      rejectUnresolved("service readiness command", service.readiness.command);
      service.readiness.args.forEach((value) => rejectUnresolved("service readiness argument", value));
    }
  }
  for (const job of definition.jobs) {
    rejectUnresolved("job name", job.name);
    for (const binding of job.matrix) {
      rejectUnresolved("matrix dimension", binding.name);
      rejectUnresolved("matrix value", binding.value);
    }
    for (const check of job.checks) {
      rejectUnresolved("check name", check.name);
      rejectUnresolved("check command", check.command);
      check.args.forEach((value) => rejectUnresolved("check argument", value));
      rejectUnresolvedEnv(check.env);
      rejectUnresolved("check working directory", check.workingDirectory);
      check.serviceDependencies.forEach((value) => rejectUnresolved("service dependency", value));
      check.retry?.flakeSignatures.forEach((value) => rejectUnresolved("flake signature", value));
      check.cachePaths.forEach((value) => rejectUnresolved("cache path", value));
      if (check.isolation !== undefined) rejectUnresolved("isolation profile", check.isolation.profile);
      for (const trigger of check.triggers) rejectUnresolved("cron expression", trigger.cronExpression);
      if (check.targetEnvironment !== undefined) {
        rejectUnresolved("target environment OCI digest", check.targetEnvironment.ociImageDigest);
        if (check.targetEnvironment.platform !== undefined) {
          rejectUnresolved("target platform os", check.targetEnvironment.platform.os);
          rejectUnresolved("target platform arch", check.targetEnvironment.platform.arch);
        }
      }
    }
  }
}

function rejectUnresolvedEnv(environment: TreadleDefinition["jobs"][number]["checks"][number]["env"]): void {
  for (const entry of environment) {
    rejectUnresolved("environment name", entry.name);
    if (entry.source.case !== undefined) rejectUnresolved("environment value", entry.source.value);
  }
}

function rejectUnresolved(kind: string, value: string): void {
  if (value.includes("${") || value.includes("{{")) {
    throw new TreadleDefinitionError(`${kind} ${JSON.stringify(value)} looks unresolved`);
  }
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

const checkClasses = {
  required: TreadleCheckClass.REQUIRED,
  advisory: TreadleCheckClass.ADVISORY,
  informational: TreadleCheckClass.INFORMATIONAL,
} as const;

const determinismClasses = {
  deterministic: TreadleDeterminismClass.DETERMINISTIC,
  nondeterministic: TreadleDeterminismClass.NONDETERMINISTIC,
} as const;

const networkAccessValues = {
  unspecified: TreadleNetworkAccess.UNSPECIFIED,
  none: TreadleNetworkAccess.NONE,
  "services-only": TreadleNetworkAccess.SERVICES_ONLY,
  full: TreadleNetworkAccess.FULL,
} as const;

const secretTiers = {
  standard: TreadleSecretTier.STANDARD,
  "trusted-runner-only": TreadleSecretTier.TRUSTED_RUNNER_ONLY,
} as const;

const triggerKinds = {
  push: TreadleTriggerKind.PUSH,
  manual: TreadleTriggerKind.MANUAL,
  cron: TreadleTriggerKind.CRON,
} as const;

const checkInputs = new WeakMap<CheckDefinition, CheckInput>();
const serviceInputs = new WeakMap<ServiceDefinition, ServiceInput>();
const jobExpanders = new WeakMap<JobDefinition, () => readonly ExpandedJob[]>();
const pipelineInputs = new WeakMap<PipelineDefinition, PipelineInput>();
