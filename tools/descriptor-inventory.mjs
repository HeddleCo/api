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
  ["ASYNCHRONOUS_OPERATIONS", "asynchronous operations"],
]);
const RPC_CONTRACT_FIELDS = new Set([
  "signing_identity",
  "signing_tier",
  "effect",
  "retry_behavior",
  "client_operation_id_required",
  "capability",
  "authorization_access",
  "authorization_role",
  "authorization_scope_source",
  "authorization_existence",
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

function enumLocalIncludingUnspecified(enumDescriptor, number, context) {
  const value = enumDescriptor.values.find(
    (candidate) => candidate.number === number,
  );
  if (value === undefined) {
    throw new Error(`descriptor metadata has unknown ${context}`);
  }
  return value.localName;
}

function messageContainsType(message, typeName, visited = new Set()) {
  if (visited.has(message.typeName)) {
    return false;
  }
  visited.add(message.typeName);
  return message.fields.some((field) => {
    const nested =
      field.fieldKind === "message" ||
      (field.fieldKind === "list" && field.listKind === "message")
        ? field.message
        : undefined;
    return (
      nested !== undefined &&
      (nested.typeName === typeName ||
        messageContainsType(nested, typeName, visited))
    );
  });
}

function requestHasNamedField(message, names) {
  return message.fields.some((field) => names.has(field.name));
}

function requestHasResourceSelector(message) {
  return message.fields.some(
    (field) =>
      field.name !== "client_operation_id" &&
      (/^(?:id|name|owner|provider|repo|resource|subject|target|username)$/.test(
        field.name,
      ) || /(?:^|_)(?:code|id|path|ref|token)$/.test(field.name)),
  );
}

function validateScopeSource(scope, input, rpc) {
  let derivable = true;
  if (scope === "REQUEST_REPOSITORY") {
    derivable = messageContainsType(input, `${PACKAGE}.RepositoryRef`);
  } else if (scope === "REQUEST_NAMESPACE") {
    derivable = requestHasNamedField(
      input,
      new Set(["namespace_path", "parent_path"]),
    );
  } else if (scope === "REQUEST_RESOURCE") {
    derivable = requestHasResourceSelector(input);
  }
  if (!derivable) {
    throw new Error(
      `authorization scope source ${scope} is not derivable from ${input.typeName}: ${rpc}`,
    );
  }
}

function validateAuthorization(metadata, maturity, rpc, input) {
  const values = [
    metadata.authorization_access,
    metadata.authorization_role,
    metadata.authorization_scope_source,
    metadata.authorization_existence,
  ];
  const unspecified = values.filter((value) => value === "UNSPECIFIED").length;
  if (unspecified !== 0) {
    if (maturity !== "PLANNED" || unspecified !== values.length) {
      throw new Error(`descriptor metadata missing authorization access/role/scope/existence: ${rpc}`);
    }
    return;
  }

  const { authorization_access: access, authorization_role: role } = metadata;
  const scope = metadata.authorization_scope_source;
  const existence = metadata.authorization_existence;
  const resourceRoles = new Set([
    "RESOURCE_READER",
    "RESOURCE_WRITER",
    "RESOURCE_ADMINISTRATOR",
    "CALLER_OR_RESOURCE_ADMINISTRATOR",
  ]);
  const resourceScopes = new Set([
    "REQUEST_REPOSITORY",
    "REQUEST_NAMESPACE",
    "REQUEST_RESOURCE",
    "CALLER_GRANTS",
  ]);
  const publicRoles = new Set(["NONE", "CALLER_BOUND"]);
  const valid =
    (role === "NONE" && scope === "NONE" && existence === "DISCLOSE") ||
    (role === "CALLER_BOUND" &&
      new Set(["CALLER_SUBJECT", "REQUEST_RESOURCE"]).has(scope)) ||
    (resourceRoles.has(role) && resourceScopes.has(scope)) ||
    (role === "GLOBAL_ADMINISTRATOR" && scope === "NONE" && existence === "DISCLOSE");
  if (!valid || (access === "PUBLIC" && !publicRoles.has(role))) {
    throw new Error(`invalid authorization combination: ${rpc}`);
  }
  validateScopeSource(scope, input, rpc);
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
  const authorizationAccess = required(
    registry,
    "getEnum",
    `${PACKAGE}.AuthorizationAccess`,
  );
  const authorizationRole = required(
    registry,
    "getEnum",
    `${PACKAGE}.AuthorizationRole`,
  );
  const authorizationScopeSource = required(
    registry,
    "getEnum",
    `${PACKAGE}.AuthorizationScopeSource`,
  );
  const authorizationExistence = required(
    registry,
    "getEnum",
    `${PACKAGE}.AuthorizationExistence`,
  );

  const rpcContractFields = new Set(
    rpcContract.message.fields.map((field) => field.name),
  );
  if (
    rpcContractFields.size !== RPC_CONTRACT_FIELDS.size ||
    [...rpcContractFields].some((name) => !RPC_CONTRACT_FIELDS.has(name))
  ) {
    throw new Error(
      "RpcContract schema changed; update the matrix renderer after contract review",
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
        const authorization = {
          authorization_access: enumLocalIncludingUnspecified(
            authorizationAccess,
            option.authorizationAccess,
            `authorization access: ${rpc}`,
          ),
          authorization_role: enumLocalIncludingUnspecified(
            authorizationRole,
            option.authorizationRole,
            `authorization role: ${rpc}`,
          ),
          authorization_scope_source: enumLocalIncludingUnspecified(
            authorizationScopeSource,
            option.authorizationScopeSource,
            `authorization scope source: ${rpc}`,
          ),
          authorization_existence: enumLocalIncludingUnspecified(
            authorizationExistence,
            option.authorizationExistence,
            `authorization existence: ${rpc}`,
          ),
        };
        validateAuthorization(authorization, maturity, rpc, method.input);
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
          ...authorization,
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
