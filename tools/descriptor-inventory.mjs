#!/usr/bin/env node

import fs from "node:fs";
import {
  createFileRegistry,
  fromBinary,
  getOption,
  hasOption,
} from "@bufbuild/protobuf";
import { FileDescriptorSetSchema } from "@bufbuild/protobuf/wkt";

const PACKAGE = "heddle.api.v1alpha1";
const CAPABILITY_LABELS = new Map([
  ["RUN_HISTORY_DETAILS", "run history/details"],
  ["STATE_COMPARISON", "state comparison"],
  ["BRANCH_PROTECTION", "branch protection"],
  ["WORKSPACE_MANAGEMENT", "workspace management"],
  ["REVIEW_DECISIONS", "review decisions"],
  ["SYNCHRONIZATION", "synchronization"],
  ["SPOOL_ADMINISTRATION", "spool administration"],
  ["REPOSITORY_INSPECTION", "repository inspection"],
  ["IDENTITY_AND_CREDENTIALS", "identity and credentials"],
  ["COLLABORATION", "collaboration"],
  ["ATTENTION_FEED", "attention feed"],
  ["PULL_REQUEST_REVIEW", "pull request review"],
  ["SEARCH", "search"],
]);

function required(registry, kind, name) {
  const value = registry[kind](name);
  if (value === undefined) {
    throw new Error(`descriptor metadata missing ${name}`);
  }
  return value;
}

function enumLocal(enumDescriptor, number, context) {
  const value = enumDescriptor.values.find(
    (candidate) => candidate.number === number,
  );
  if (value === undefined || value.number === 0) {
    throw new Error(`descriptor metadata missing ${context}`);
  }
  return value.localName;
}

function main() {
  if (process.argv.length !== 3) {
    throw new Error("usage: descriptor-inventory.mjs <file-descriptor-set>");
  }
  const descriptorSet = fromBinary(
    FileDescriptorSetSchema,
    fs.readFileSync(process.argv[2]),
  );
  const registry = createFileRegistry(descriptorSet);
  const serviceContract = required(
    registry,
    "getExtension",
    `${PACKAGE}.service_contract`,
  );
  const rpcContract = required(
    registry,
    "getExtension",
    `${PACKAGE}.rpc_contract`,
  );
  const deploymentTarget = required(
    registry,
    "getEnum",
    `${PACKAGE}.DeploymentTarget`,
  );
  const serviceMaturity = required(
    registry,
    "getEnum",
    `${PACKAGE}.ServiceMaturity`,
  );
  const signingIdentity = required(
    registry,
    "getEnum",
    `${PACKAGE}.StableSigningIdentity`,
  );
  const signingTier = required(registry, "getEnum", `${PACKAGE}.SigningTier`);
  const rpcEffect = required(registry, "getEnum", `${PACKAGE}.RpcEffect`);
  const retryBehavior = required(
    registry,
    "getEnum",
    `${PACKAGE}.RetryBehavior`,
  );
  const capabilityArea = required(
    registry,
    "getEnum",
    `${PACKAGE}.CapabilityArea`,
  );

  const authorizationFields = rpcContract.message.fields
    .map((field) => field.name)
    .filter((name) => /authorization|role|scope/.test(name));
  if (authorizationFields.length !== 0) {
    throw new Error(
      "authorization role/scope metadata now exists; update the matrix renderer",
    );
  }

  const inventory = {};
  const files = [...registry.files].filter(
    (file) => file.proto.package === PACKAGE,
  );
  for (const file of files) {
    for (const service of file.services) {
      if (!hasOption(service, serviceContract)) {
        throw new Error(
          `descriptor metadata missing service contract: ${service.typeName}`,
        );
      }
      const serviceOption = getOption(service, serviceContract);
      if (serviceOption.deploymentTargets.length === 0) {
        throw new Error(
          `descriptor metadata missing deployment target: ${service.typeName}`,
        );
      }
      const deploymentTargets = serviceOption.deploymentTargets
        .map((number) =>
          enumLocal(
            deploymentTarget,
            number,
            `deployment target: ${service.typeName}`,
          ),
        )
        .sort();
      const maturity = enumLocal(
        serviceMaturity,
        serviceOption.maturity,
        `service maturity: ${service.typeName}`,
      );

      for (const method of service.methods) {
        const rpc = `${service.typeName}/${method.name}`;
        if (!hasOption(method, rpcContract)) {
          throw new Error(`descriptor metadata missing RPC contract: ${rpc}`);
        }
        const option = getOption(method, rpcContract);
        const capabilityName = enumLocal(
          capabilityArea,
          option.capability,
          `capability: ${rpc}`,
        );
        const capability = CAPABILITY_LABELS.get(capabilityName);
        if (capability === undefined) {
          throw new Error(`descriptor capability is not catalogued: ${rpc}`);
        }
        if (inventory[rpc] !== undefined) {
          throw new Error(`descriptor contains duplicate RPC: ${rpc}`);
        }
        inventory[rpc] = {
          rpc,
          service: service.typeName,
          method: method.name,
          capability,
          deployment_targets: deploymentTargets,
          maturity,
          signing_identity: enumLocal(
            signingIdentity,
            option.signingIdentity,
            `signing identity: ${rpc}`,
          ),
          signing_tier: enumLocal(
            signingTier,
            option.signingTier,
            `signing tier: ${rpc}`,
          ),
          effect: enumLocal(rpcEffect, option.effect, `effect: ${rpc}`),
          retry_behavior: enumLocal(
            retryBehavior,
            option.retryBehavior,
            `retry behavior: ${rpc}`,
          ),
          client_operation_id_required: option.clientOperationIdRequired,
          client_streaming: method.proto.clientStreaming,
          server_streaming: method.proto.serverStreaming,
        };
      }
    }
  }
  if (Object.keys(inventory).length === 0) {
    throw new Error(`descriptor contains no RPCs in ${PACKAGE}`);
  }
  const sorted = Object.fromEntries(
    Object.entries(inventory).sort(([left], [right]) =>
      left.localeCompare(right),
    ),
  );
  process.stdout.write(`${JSON.stringify(sorted)}\n`);
}

try {
  main();
} catch (error) {
  process.stderr.write(
    `${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exitCode = 1;
}
