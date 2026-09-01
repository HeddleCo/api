#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { TreadleDefinitionError } from "./dist/treadle.js";
import { emitPipeline } from "./dist/treadle-authoring.js";

export const TREADLE_DEFINITION_BIN = "treadle.definition.bin";
export const TREADLE_LOCK_JSON = "treadle.lock.json";

/** Load `export default definePipeline(...)` from a pipeline module. */
export async function loadPipelineDefinition(pipelinePath) {
  const resolved = resolve(pipelinePath);
  const module = await import(pathToFileURL(resolved).href);
  if (module.default === undefined) {
    throw new TreadleDefinitionError(
      `pipeline file ${JSON.stringify(resolved)} has no default export`,
    );
  }
  return module.default;
}

/**
 * Emit a pipeline module to `.heddle/treadle.definition.bin` and
 * `.heddle/treadle.lock.json`. `outDir` defaults to `{cwd}/.heddle`.
 */
export async function compileTreadlePipeline({ pipelinePath, outDir }) {
  const emission = emitPipeline(await loadPipelineDefinition(pipelinePath));
  const resolvedOutDir = resolve(outDir ?? join(process.cwd(), ".heddle"));
  await mkdir(resolvedOutDir, { recursive: true });
  const definitionPath = join(resolvedOutDir, TREADLE_DEFINITION_BIN);
  const lockPath = join(resolvedOutDir, TREADLE_LOCK_JSON);
  await writeFile(definitionPath, emission.canonicalBytes);
  await writeFile(lockPath, emission.lockFile.contents);
  return { outDir: resolvedOutDir, definitionPath, lockPath, emission };
}

export function parseCompileArgs(argv) {
  let pipelinePath;
  let outDir;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--out-dir") {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith("-")) {
        throw new TreadleDefinitionError("treadle-compile: --out-dir requires a directory");
      }
      outDir = value;
      index += 1;
      continue;
    }
    if (arg.startsWith("--out-dir=")) {
      outDir = arg.slice("--out-dir=".length);
      if (outDir.length === 0) {
        throw new TreadleDefinitionError("treadle-compile: --out-dir requires a directory");
      }
      continue;
    }
    if (arg.startsWith("-")) {
      throw new TreadleDefinitionError(`treadle-compile: unknown option ${JSON.stringify(arg)}`);
    }
    if (pipelinePath !== undefined) {
      throw new TreadleDefinitionError("treadle-compile: unexpected extra argument");
    }
    pipelinePath = arg;
  }
  if (pipelinePath === undefined) {
    throw new TreadleDefinitionError("treadle-compile: pipeline file path is required");
  }
  return { pipelinePath, outDir };
}

export async function main(argv = process.argv.slice(2)) {
  const artifacts = await compileTreadlePipeline(parseCompileArgs(argv));
  process.stdout.write(`${artifacts.definitionPath}\n${artifacts.lockPath}\n`);
  return artifacts;
}

const invoked = process.argv[1];
if (invoked !== undefined && import.meta.url === pathToFileURL(resolve(invoked)).href) {
  main().catch((error) => {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  });
}
