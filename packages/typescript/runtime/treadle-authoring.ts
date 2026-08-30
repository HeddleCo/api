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

export interface IsolationHintsInput {
  readonly profile?: string;
  readonly networkAccess?: NetworkAccess;
  readonly cpuMillis?: number;
  readonly memoryBytes?: bigint;
  readonly processLimit?: number;
}

export interface RetryInput {
  readonly maxRetries?: number;
  readonly flakeSignatures?: readonly string[];
}

export interface TargetEnvironment {
  readonly ociImageDigest: string;
  readonly platform: {
    readonly os: string;
    readonly arch: string;
  };
}

export type TriggerInput =
  | { readonly kind: "push" | "manual" }
  | { readonly kind: "cron"; readonly cronExpression: string };

/**
 * Fields a pipeline, language pack, or check may omit. Emit fills only omitted
 * fields so the protobuf still carries every required v1 message.
 */
export interface CheckDefaults {
  readonly class?: CheckClass;
  readonly timeoutSeconds?: number;
  readonly env?: Environment;
  readonly workingDirectory?: string;
  readonly serviceDependencies?: readonly string[];
  readonly retry?: RetryInput;
  /** Shorthand for `retry.flakeSignatures`. */
  readonly flake?: readonly string[];
  readonly cachePaths?: readonly string[];
  readonly isolation?: IsolationHintsInput;
  readonly triggers?: readonly TriggerInput[];
  readonly supersedeOlderRuns?: boolean;
  readonly targetEnvironment?: TargetEnvironment;
  readonly determinismClass?: DeterminismClass;
}

/**
 * Authoring input for `defineCheck()`. Identity fields are required; every
 * other field may be omitted and filled from pipeline, pack, or SDK defaults.
 * Fully-specified checks keep working: present fields are never overwritten.
 */
export interface CheckInput extends CheckDefaults {
  readonly name: string;
  readonly command: string;
  readonly args: readonly string[];
}

/** Extra options for language-pack helpers and `test()` / `sh()`. */
export interface CheckOptions extends CheckDefaults {
  readonly name?: string;
  readonly args?: readonly string[];
  /**
   * Rust clippy pack default is `true` (append `-- -D warnings`, matching
   * heddle CI). Set `false` to leave the author's args unchanged.
   */
  readonly denyWarnings?: boolean;
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

export type JobMap = Readonly<Record<string, readonly CheckDefinition[]>>;

export interface PipelineInput {
  readonly name: string;
  readonly defaults?: CheckDefaults;
  readonly jobs: readonly JobDefinition[] | JobMap;
  readonly services?: readonly ServiceDefinition[];
  readonly secretRefs?: readonly SecretReference[];
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

/**
 * Runtime language pack. Packs are values (not generic type parameters — those
 * erase) and still emit argv `command` + `args`.
 */
export interface LanguagePack {
  readonly id: string;
  readonly command: string;
  readonly defaults: CheckDefaults;
}

/**
 * Dummy OCI image digest used by the rust pack and by `hostTargetEnvironment()`.
 *
 * Host-exec v0 (`heddle ci run --local`) does not pull this image; it only
 * admits matching `os`/`arch`. Reuses the v1 conformance fixture pin
 * (`tests/fixtures/treadle-definition-v1.json` `unit` check: `sha256:` + 64
 * `1` digits). Override the digest before signing a production definition
 * against a real image.
 */
export const HOST_EXEC_DUMMY_OCI_IMAGE_DIGEST = `sha256:${"1".repeat(64)}`;

/**
 * Rust-pack default `target_environment`.
 *
 * linux/amd64 plus {@link HOST_EXEC_DUMMY_OCI_IMAGE_DIGEST}. Golden and
 * conformance tests keep this pin so compact Fast Lane bytes stay stable.
 * A pipeline that must run locally has to override with
 * `defaults.targetEnvironment: hostTargetEnvironment()` — heddle#1616
 * `admit_host_exec` refuses an os/arch mismatch, and this pin is not the
 * authoring host.
 */
export const RUST_PACK_TARGET_ENVIRONMENT: TargetEnvironment = Object.freeze({
  ociImageDigest: HOST_EXEC_DUMMY_OCI_IMAGE_DIGEST,
  platform: Object.freeze({ os: "linux", arch: "amd64" }),
});

export interface HostTargetEnvironmentInput {
  readonly platform?: string;
  readonly arch?: string;
  readonly ociImageDigest?: string;
}

/**
 * `target_environment` for the current authoring host.
 *
 * Maps `process.platform` / `process.arch` onto proto platform strings
 * (`darwin`/`linux`/`windows`, `amd64`/`arm64`). The image digest stays the
 * host-exec dummy pin unless overridden. Local-run authors pass this on
 * pipeline `defaults.targetEnvironment`.
 */
export function hostTargetEnvironment(
  input: HostTargetEnvironmentInput = {},
): TargetEnvironment {
  return Object.freeze({
    ociImageDigest: input.ociImageDigest ?? HOST_EXEC_DUMMY_OCI_IMAGE_DIGEST,
    platform: Object.freeze({
      os: mapHostOs(input.platform ?? hostProcessField("platform")),
      arch: mapHostArch(input.arch ?? hostProcessField("arch")),
    }),
  });
}

function hostProcessField(field: "platform" | "arch"): string {
  const runtime = globalThis as typeof globalThis & {
    process?: { platform?: unknown; arch?: unknown };
  };
  const value = runtime.process?.[field];
  if (typeof value !== "string" || value.length === 0) {
    throw new TreadleDefinitionError(`hostTargetEnvironment: process.${field} is unavailable`);
  }
  return value;
}

function mapHostOs(platform: string): "darwin" | "linux" | "windows" {
  switch (platform) {
    case "darwin":
      return "darwin";
    case "linux":
      return "linux";
    case "win32":
      return "windows";
    default:
      throw new TreadleDefinitionError(
        `hostTargetEnvironment: unsupported process.platform ${JSON.stringify(platform)}; expected darwin, linux, or win32`,
      );
  }
}

function mapHostArch(arch: string): "amd64" | "arm64" {
  switch (arch) {
    case "x64":
      return "amd64";
    case "arm64":
      return "arm64";
    default:
      throw new TreadleDefinitionError(
        `hostTargetEnvironment: unsupported process.arch ${JSON.stringify(arch)}; expected x64 or arm64`,
      );
  }
}

/** SDK defaults applied only to fields the author, pipeline, and pack omit. */
export const AUTHORING_CHECK_DEFAULTS = Object.freeze({
  name: "",
  command: "",
  args: Object.freeze([]) as readonly string[],
  class: "required" as const,
  timeoutSeconds: 1800,
  env: Object.freeze({}) as Environment,
  workingDirectory: "",
  serviceDependencies: Object.freeze([]) as readonly string[],
  retry: Object.freeze({
    maxRetries: 0,
    flakeSignatures: Object.freeze([]) as readonly string[],
  }),
  cachePaths: Object.freeze([]) as readonly string[],
  isolation: Object.freeze({
    profile: "",
    networkAccess: "unspecified" as const,
    cpuMillis: 0,
    memoryBytes: 0n,
    processLimit: 0,
  }),
  triggers: Object.freeze([{ kind: "push" as const }]) as readonly TriggerInput[],
  supersedeOlderRuns: false,
  targetEnvironment: RUST_PACK_TARGET_ENVIRONMENT,
  determinismClass: "deterministic" as const,
});

const DEFAULT_FLAKE_MAX_RETRIES = 2;

const rustPack: LanguagePack = {
  id: "rust",
  command: "cargo",
  defaults: Object.freeze({
    cachePaths: Object.freeze(["target"]),
    targetEnvironment: RUST_PACK_TARGET_ENVIRONMENT,
  }),
};

export const rust: LanguagePack & {
  build(args: readonly string[], opts?: CheckOptions): CheckDefinition;
  clippy(args: readonly string[], opts?: CheckOptions): CheckDefinition;
  test(args: readonly string[], opts?: CheckOptions): CheckDefinition;
  fmt(opts?: CheckOptions): CheckDefinition;
} = {
  ...rustPack,
  build(args, opts) {
    return languageVerbCheck(rustPack, "build", args, opts);
  },
  clippy(args, opts) {
    return languageVerbCheck(rustPack, "clippy", clippyArgs(args, opts), opts);
  },
  test(args, opts) {
    return test(rustPack, { ...opts, args });
  },
  fmt(opts) {
    return languageVerbCheck(rustPack, "fmt", opts?.args ?? ["--check"], opts);
  },
};

interface ExpandedJob {
  readonly name: string;
  readonly matrix: Readonly<Record<string, string>>;
  readonly checks: readonly CheckDefinition[];
}

interface AuthoredCheck {
  readonly input: CheckInput;
  readonly packDefaults?: CheckDefaults;
}

interface ResolvedIsolation {
  readonly profile: string;
  readonly networkAccess: NetworkAccess;
  readonly cpuMillis: number;
  readonly memoryBytes: bigint;
  readonly processLimit: number;
}

interface ResolvedRetry {
  readonly maxRetries: number;
  readonly flakeSignatures: readonly string[];
}

interface ResolvedCheckInput {
  readonly name: string;
  readonly command: string;
  readonly args: readonly string[];
  readonly class: CheckClass;
  readonly timeoutSeconds: number;
  readonly env: Environment;
  readonly workingDirectory: string;
  readonly serviceDependencies: readonly string[];
  readonly retry: ResolvedRetry;
  readonly cachePaths: readonly string[];
  readonly isolation: ResolvedIsolation;
  readonly triggers: readonly TriggerInput[];
  readonly supersedeOlderRuns: boolean;
  readonly targetEnvironment: TargetEnvironment;
  readonly determinismClass: DeterminismClass;
}

/** Declare a names-only secret grant that can also be used as an env value. */
export function secretRef(input: SecretReferenceInput): SecretReference {
  return Object.freeze({
    name: input.name,
    provider: input.provider ?? "",
    tier: input.tier,
  });
}

/** Declare one argv-only signable check. Omitted fields are filled at emit. */
export function defineCheck(input: CheckInput): CheckDefinition {
  return registerCheck({ input });
}

/**
 * Generic language-pack test helper. Packs sit on this: `rust.test(args, opts)`
 * is `test(rust, { args, ...opts })`. Always emits `command` + argv, never a
 * shell string.
 */
export function test(lang: LanguagePack, opts: CheckOptions = {}): CheckDefinition {
  return languageVerbCheck(lang, "test", opts.args ?? [], opts);
}

/**
 * Non-cargo argv check. `name` is the check name; `args` is the process
 * argument vector passed to `sh`. Never a shell command string.
 */
export function sh(
  name: string,
  args: readonly string[],
  opts?: CheckOptions,
): CheckDefinition {
  return registerCheck({
    input: {
      name,
      command: "sh",
      args: [...args],
      ...checkOptionDefaults(opts),
    },
  });
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
  const jobs = pipelineJobs(input);
  const definition = create(TreadleDefinitionSchema, {
    formatVersion: TREADLE_DEFINITION_FORMAT_VERSION,
    name: input.name,
    jobs: jobs.flatMap((definition) =>
      requireDefined(jobExpanders, definition, "job", "job")().map((expanded) =>
        buildJob(expanded, input.defaults),
      ),
    ),
    services: (input.services ?? []).map(buildService),
    secretRefs: (input.secretRefs ?? []).map((reference) =>
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

function pipelineJobs(input: PipelineInput): readonly JobDefinition[] {
  if (Array.isArray(input.jobs)) return input.jobs;
  return Object.entries(input.jobs).map(([name, checks]) => {
    if (!Array.isArray(checks)) {
      throw new TreadleDefinitionError(
        `jobs.${JSON.stringify(name)} must be a check list; use job() in the jobs array for matrix jobs`,
      );
    }
    return job({ name, checks });
  });
}

function buildJob(job: ExpandedJob, defaults: CheckDefaults | undefined): TreadleJob {
  return create(TreadleJobSchema, {
    name: job.name,
    matrix: Object.entries(job.matrix).map(([name, value]) =>
      create(TreadleMatrixValueSchema, { name, value }),
    ),
    checks: job.checks.map((definition) => {
      const authored = requireDefined(checkInputs, definition, "check", "defineCheck");
      const input = resolveCheckInput(authored, defaults);
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

function resolveCheckInput(
  authored: AuthoredCheck,
  pipelineDefaults: CheckDefaults | undefined,
): ResolvedCheckInput {
  const author = authored.input;
  const pack = authored.packDefaults;
  const isolation = resolveIsolation(author.isolation, pipelineDefaults?.isolation, pack?.isolation);
  return {
    name: author.name,
    command: author.command,
    args: author.args,
    class: firstDefined(author.class, pipelineDefaults?.class, pack?.class, AUTHORING_CHECK_DEFAULTS.class),
    timeoutSeconds: firstDefined(
      author.timeoutSeconds,
      pipelineDefaults?.timeoutSeconds,
      pack?.timeoutSeconds,
      AUTHORING_CHECK_DEFAULTS.timeoutSeconds,
    ),
    env: firstDefined(author.env, pipelineDefaults?.env, pack?.env, AUTHORING_CHECK_DEFAULTS.env),
    workingDirectory: firstDefined(
      author.workingDirectory,
      pipelineDefaults?.workingDirectory,
      pack?.workingDirectory,
      AUTHORING_CHECK_DEFAULTS.workingDirectory,
    ),
    serviceDependencies: firstDefined(
      author.serviceDependencies,
      pipelineDefaults?.serviceDependencies,
      pack?.serviceDependencies,
      AUTHORING_CHECK_DEFAULTS.serviceDependencies,
    ),
    retry: resolveRetry(author, pipelineDefaults, pack),
    cachePaths: firstDefined(
      author.cachePaths,
      pipelineDefaults?.cachePaths,
      pack?.cachePaths,
      AUTHORING_CHECK_DEFAULTS.cachePaths,
    ),
    isolation,
    triggers: firstDefined(
      author.triggers,
      pipelineDefaults?.triggers,
      pack?.triggers,
      AUTHORING_CHECK_DEFAULTS.triggers,
    ),
    supersedeOlderRuns: firstDefined(
      author.supersedeOlderRuns,
      pipelineDefaults?.supersedeOlderRuns,
      pack?.supersedeOlderRuns,
      AUTHORING_CHECK_DEFAULTS.supersedeOlderRuns,
    ),
    targetEnvironment: firstDefined(
      author.targetEnvironment,
      pipelineDefaults?.targetEnvironment,
      pack?.targetEnvironment,
      AUTHORING_CHECK_DEFAULTS.targetEnvironment,
    ),
    determinismClass: firstDefined(
      author.determinismClass,
      pipelineDefaults?.determinismClass,
      pack?.determinismClass,
      AUTHORING_CHECK_DEFAULTS.determinismClass,
    ),
  };
}

function resolveIsolation(
  author: IsolationHintsInput | undefined,
  pipeline: IsolationHintsInput | undefined,
  pack: IsolationHintsInput | undefined,
): ResolvedIsolation {
  const fallback = AUTHORING_CHECK_DEFAULTS.isolation;
  return {
    profile: firstDefined(author?.profile, pipeline?.profile, pack?.profile, fallback.profile),
    networkAccess: firstDefined(
      author?.networkAccess,
      pipeline?.networkAccess,
      pack?.networkAccess,
      fallback.networkAccess,
    ),
    cpuMillis: firstDefined(author?.cpuMillis, pipeline?.cpuMillis, pack?.cpuMillis, fallback.cpuMillis),
    memoryBytes: firstDefined(
      author?.memoryBytes,
      pipeline?.memoryBytes,
      pack?.memoryBytes,
      fallback.memoryBytes,
    ),
    processLimit: firstDefined(
      author?.processLimit,
      pipeline?.processLimit,
      pack?.processLimit,
      fallback.processLimit,
    ),
  };
}

function resolveRetry(
  author: CheckDefaults,
  pipeline: CheckDefaults | undefined,
  pack: CheckDefaults | undefined,
): ResolvedRetry {
  const flakeSignatures = firstDefined(
    author.retry?.flakeSignatures,
    author.flake,
    pipeline?.retry?.flakeSignatures,
    pipeline?.flake,
    pack?.retry?.flakeSignatures,
    pack?.flake,
    AUTHORING_CHECK_DEFAULTS.retry.flakeSignatures,
  );
  const maxRetries = firstDefined(
    author.retry?.maxRetries,
    pipeline?.retry?.maxRetries,
    pack?.retry?.maxRetries,
    flakeSignatures.length > 0 ? DEFAULT_FLAKE_MAX_RETRIES : AUTHORING_CHECK_DEFAULTS.retry.maxRetries,
  );
  return { maxRetries, flakeSignatures };
}

function firstDefined<T>(...values: Array<T | undefined>): T {
  for (const value of values) {
    if (value !== undefined) return value;
  }
  throw new TreadleDefinitionError("internal authoring default is missing");
}

function languageVerbCheck(
  pack: LanguagePack,
  verb: string,
  args: readonly string[],
  opts?: CheckOptions,
): CheckDefinition {
  return registerCheck({
    input: {
      name: opts?.name ?? verb,
      command: pack.command,
      args: [verb, ...args],
      ...checkOptionDefaults(opts),
    },
    packDefaults: pack.defaults,
  });
}

function clippyArgs(args: readonly string[], opts?: CheckOptions): readonly string[] {
  const denyWarnings = opts?.denyWarnings ?? true;
  if (!denyWarnings || alreadyDeniesWarnings(args)) return args;
  return [...args, "--", "-D", "warnings"];
}

function alreadyDeniesWarnings(args: readonly string[]): boolean {
  const separator = args.indexOf("--");
  if (separator === -1) return false;
  const rustcArgs = args.slice(separator + 1);
  for (let index = 0; index < rustcArgs.length; index += 1) {
    const flag = rustcArgs[index];
    if (flag === "-Dwarnings") return true;
    if (flag === "-D" && rustcArgs[index + 1] === "warnings") return true;
  }
  return false;
}

function checkOptionDefaults(opts?: CheckOptions): CheckDefaults {
  if (opts === undefined) return {};
  const {
    name: _name,
    args: _args,
    denyWarnings: _denyWarnings,
    ...defaults
  } = opts;
  return defaults;
}

function registerCheck(authored: AuthoredCheck): CheckDefinition {
  const definition = Object.freeze({}) as CheckDefinition;
  checkInputs.set(definition, authored);
  return definition;
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

const checkInputs = new WeakMap<CheckDefinition, AuthoredCheck>();
const serviceInputs = new WeakMap<ServiceDefinition, ServiceInput>();
const jobExpanders = new WeakMap<JobDefinition, () => readonly ExpandedJob[]>();
const pipelineInputs = new WeakMap<PipelineDefinition, PipelineInput>();
