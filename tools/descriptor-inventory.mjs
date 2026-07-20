#!/usr/bin/env node

import fs from "node:fs";
import {
  createFileRegistry,
  fromBinary,
  getOption,
  hasOption,
  ScalarType,
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
  "authorization_request_targets",
  "authorization_multi_target",
  "deployment_targets",
  "maturity",
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
  if (message.typeName === typeName) {
    return true;
  }
  if (visited.has(message.typeName)) {
    return false;
  }
  visited.add(message.typeName);
  return message.fields.some((field) => {
    const nested =
      field.fieldKind === "message" ||
      (field.fieldKind === "list" && field.listKind === "message") ||
      (field.fieldKind === "map" && field.mapKind === "message")
        ? field.message
        : undefined;
    return (
      nested !== undefined && messageContainsType(nested, typeName, visited)
    );
  });
}

function nestedMessage(field) {
  if (
    field.fieldKind === "message" ||
    (field.fieldKind === "list" && field.listKind === "message") ||
    (field.fieldKind === "map" && field.mapKind === "message")
  ) {
    return field.message;
  }
  return undefined;
}

function resolveRequestPath(input, path, rpc) {
  if (!/^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*$/.test(path)) {
    throw new Error(`invalid authorization request path ${path}: ${rpc}`);
  }
  const segments = path.split(".");
  let message = input;
  let field;
  for (const [index, segment] of segments.entries()) {
    field = message.fields.find((candidate) => candidate.name === segment);
    if (field === undefined) {
      throw new Error(
        `authorization request path ${path} does not exist in ${input.typeName}: ${rpc}`,
      );
    }
    if (index !== segments.length - 1) {
      message = nestedMessage(field);
      if (message === undefined) {
        throw new Error(
          `authorization request path ${path} traverses non-message field ${segment}: ${rpc}`,
        );
      }
    }
  }
  return field;
}

function validateScopeSource(
  scope,
  requestTargets,
  multiTarget,
  input,
  rpc,
  contractRole,
) {
  const requestScopes = new Set([
    "REQUEST_REPOSITORY",
    "REQUEST_NAMESPACE",
    "REQUEST_RESOURCE",
  ]);
  if (!requestScopes.has(scope)) {
    if (requestTargets.length !== 0) {
      throw new Error(
        `authorization request targets require a request-derived scope source: ${rpc}`,
      );
    }
    if (multiTarget) {
      throw new Error(`authorization multi-target declaration mismatch: ${rpc}`);
    }
    return;
  }
  if (requestTargets.length === 0) {
    throw new Error(`authorization request targets missing for ${scope}: ${rpc}`);
  }
  const requestPaths = requestTargets.map((target) => target.path);
  if (new Set(requestPaths).size !== requestPaths.length) {
    throw new Error(`duplicate authorization request path: ${rpc}`);
  }
  if (multiTarget !== (requestTargets.length > 1)) {
    throw new Error(`authorization multi-target declaration mismatch: ${rpc}`);
  }
  const targetRoles = new Set([
    "CALLER_BOUND",
    "RESOURCE_READER",
    "RESOURCE_WRITER",
    "RESOURCE_MAINTAINER",
    "RESOURCE_ADMINISTRATOR",
    "RESOURCE_OWNER",
    "CALLER_OR_RESOURCE_ADMINISTRATOR",
  ]);
  if (
    requestTargets.some((target) => !targetRoles.has(target.role)) ||
    !requestTargets.some((target) => target.role === contractRole)
  ) {
    throw new Error(`invalid authorization request target role: ${rpc}`);
  }
  const fields = requestPaths.map((path) => resolveRequestPath(input, path, rpc));
  if (
    scope === "REQUEST_REPOSITORY" &&
    fields.some(
      (field) => nestedMessage(field)?.typeName !== `${PACKAGE}.RepositoryRef`,
    )
  ) {
    throw new Error(
      `authorization scope source REQUEST_REPOSITORY must target RepositoryRef fields: ${rpc}`,
    );
  }
  if (
    scope === "REQUEST_NAMESPACE" &&
    fields.some(
      (field) =>
        field.fieldKind !== "scalar" || field.scalar !== ScalarType.STRING,
    )
  ) {
    throw new Error(
      `authorization scope source REQUEST_NAMESPACE must target string fields: ${rpc}`,
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
    throw new Error(`descriptor metadata missing authorization access/role/scope/existence: ${rpc}`);
  }
  const undecided = values.filter((value) => value === "PLANNED_UNDECIDED").length;
  if (undecided !== 0) {
    if (
      maturity !== "PLANNED" ||
      undecided !== values.length ||
      metadata.authorization_request_targets.length !== 0 ||
      metadata.authorization_multi_target
    ) {
      throw new Error(`invalid planned-undecided authorization contract: ${rpc}`);
    }
    return;
  }

  const { authorization_access: access, authorization_role: role } = metadata;
  const scope = metadata.authorization_scope_source;
  const existence = metadata.authorization_existence;
  const resourceRoles = new Set([
    "RESOURCE_READER",
    "RESOURCE_WRITER",
    "RESOURCE_MAINTAINER",
    "RESOURCE_ADMINISTRATOR",
    "RESOURCE_OWNER",
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
  validateScopeSource(
    scope,
    metadata.authorization_request_targets,
    metadata.authorization_multi_target,
    input,
    rpc,
    role,
  );
}

function authorizationMatches(metadata, expected) {
  return Object.entries(expected).every(
    ([field, value]) => metadata[field] === value,
  );
}

function validateSensitiveResponseAuthorization(metadata, maturity, output, rpc) {
  if (
    maturity === "PLANNED" &&
    metadata.authorization_access === "PLANNED_UNDECIDED"
  ) {
    return;
  }
  if (messageContainsType(output, `${PACKAGE}.CredentialInfo`)) {
    const safe =
      metadata.authorization_access === "AUTHENTICATED_PRINCIPAL" &&
      metadata.authorization_role !== "NONE" &&
      metadata.authorization_scope_source !== "NONE" &&
      metadata.authorization_existence === "HIDE";
    if (!safe) {
      throw new Error(
        `credential information requires scoped, existence-hiding authorization: ${rpc}`,
      );
    }
  }

  const handleDirectory =
    messageContainsType(output, `${PACKAGE}.HandlePrincipal`) ||
    messageContainsType(output, `${PACKAGE}.GetHandleStatusResponse`);
  if (
    handleDirectory &&
    !authorizationMatches(metadata, {
      authorization_access: "AUTHENTICATED_PRINCIPAL",
      authorization_role: "NONE",
      authorization_scope_source: "NONE",
      authorization_existence: "DISCLOSE",
    })
  ) {
    throw new Error(`handle directory requires an authenticated bearer: ${rpc}`);
  }

  if (
    messageContainsType(output, `${PACKAGE}.ResolvedPrincipal`) &&
    !authorizationMatches(metadata, {
      authorization_access: "AUTHENTICATED_PRINCIPAL",
      authorization_role: "RESOURCE_READER",
      authorization_scope_source: "CALLER_GRANTS",
      authorization_existence: "HIDE",
    })
  ) {
    throw new Error(`subject directory must be limited to caller grants: ${rpc}`);
  }
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
        const methodDeploymentTargets =
          option.deploymentTargets.length === 0
            ? deploymentTargets
            : option.deploymentTargets
                .map((number) =>
                  enumLocal(
                    deploymentTarget,
                    number,
                    `deployment target: ${rpc}`,
                  ),
                )
                .sort();
        const methodMaturity =
          option.maturity === 0
            ? maturity
            : enumLocal(serviceMaturity, option.maturity, `maturity: ${rpc}`);
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
          authorization_request_targets: option.authorizationRequestTargets.map(
            (target) => ({
              path: target.path,
              role: enumLocal(
                authorizationRole,
                target.role,
                `authorization request target role: ${rpc}:${target.path}`,
              ),
            }),
          ),
          authorization_multi_target: option.authorizationMultiTarget,
        };
        validateAuthorization(authorization, methodMaturity, rpc, method.input);
        validateSensitiveResponseAuthorization(
          authorization,
          methodMaturity,
          method.output,
          rpc,
        );
        inventory[rpc] = {
          rpc,
          service: service.typeName,
          method: method.name,
          capability,
          deployment_targets: methodDeploymentTargets,
          maturity: methodMaturity,
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
