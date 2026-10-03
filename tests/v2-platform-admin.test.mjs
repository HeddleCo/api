import test from "node:test";
import assert from "node:assert/strict";
import { create, fromBinary, getOption, toBinary } from "@bufbuild/protobuf";
import {
  PlatformAdminService, PlatformAuthorizationRequestSchema,
  PlatformAuthorizationResponseSchema, Capability, createServiceClient,
} from "@heddleco/api/v2";
import {
  rpc_contract, service_contract, AuthorizationAccess, AuthorizationExistence,
  AuthorizationRole, AuthorizationScopeSource, CapabilityArea, DeploymentTarget,
  RetryBehavior, RpcEffect, ServiceMaturity, SigningTier, StableSigningIdentity,
} from "../packages/typescript/dist/common/contract_pb.js";

const checks = [
  ["authorizeEmailTemplates", "AuthorizeEmailTemplates", Capability.PLATFORM_EMAIL_TEMPLATES, 6],
  ["authorizeEmailDelivery", "AuthorizeEmailDelivery", Capability.PLATFORM_EMAIL_DELIVERY, 7],
  ["authorizeAnalytics", "AuthorizeAnalytics", Capability.PLATFORM_ANALYTICS, 8],
  ["authorizeInvitationDirectory", "AuthorizeInvitationDirectory", Capability.PLATFORM_INVITATION_DIRECTORY, 9],
];

test("platform service exports all four exact authorization contracts", () => {
  const service = getOption(PlatformAdminService, service_contract);
  assert.deepEqual(service.deploymentTargets, [DeploymentTarget.WEFT]);
  assert.equal(service.maturity, ServiceMaturity.PLANNED);
  assert.equal(PlatformAdminService.methods.length, 4);
  assert.equal(CapabilityArea.PLATFORM_ADMINISTRATION, 17);
  for (const [localName, name, capability, number] of checks) {
    assert.equal(capability, number);
    const method = PlatformAdminService.method[localName];
    assert.equal(method.name, name);
    assert.equal(method.methodKind, "unary");
    assert.equal(method.input, PlatformAuthorizationRequestSchema);
    assert.equal(method.output, PlatformAuthorizationResponseSchema);
    const contract = getOption(method, rpc_contract);
    assert.equal(contract.signingIdentity, StableSigningIdentity.AUTHENTICATED_PRINCIPAL, name);
    assert.equal(contract.signingTier, SigningTier.PROOF_OF_POSSESSION, name);
    assert.equal(contract.effect, RpcEffect.READ_ONLY, name);
    assert.equal(contract.retryBehavior, RetryBehavior.SAFE, name);
    assert.equal(contract.capability, CapabilityArea.PLATFORM_ADMINISTRATION, name);
    assert.equal(contract.authorizationAccess, AuthorizationAccess.AUTHENTICATED_PRINCIPAL, name);
    assert.equal(contract.authorizationRole, AuthorizationRole.GLOBAL_ADMINISTRATOR, name);
    assert.equal(contract.authorizationScopeSource, AuthorizationScopeSource.CALLER_GRANTS, name);
    assert.equal(contract.authorizationExistence, AuthorizationExistence.HIDE, name);
    assert.equal(contract.clientOperationIdRequired, false);
    assert.deepEqual(contract.authorizationRequestTargets, []);
  }
});

for (const [localName, name, capability] of checks) {
  test(`typed client calls ${name} online each time and preserves current advice`, async () => {
    const path = `/heddle.api.v1alpha2.PlatformAdminService/${name}`;
    let calls = 0;
    const transport = {
      async unary(method, bytes) {
        calls++;
        assert.equal(method, PlatformAdminService.method[localName]);
        assert.deepEqual(fromBinary(PlatformAuthorizationRequestSchema, bytes), create(PlatformAuthorizationRequestSchema));
        return toBinary(PlatformAuthorizationResponseSchema, create(PlatformAuthorizationResponseSchema, {
          action: { method: path, capability, implemented: true, authorized: calls === 1 },
        }));
      },
    };
    const unsupported = createServiceClient(PlatformAdminService, transport, new Set());
    await assert.rejects(unsupported[localName]({}), (error) => error.reason === "not_implemented");
    assert.equal(calls, 0);
    const client = createServiceClient(PlatformAdminService, transport, new Set([path]));
    const first = await client[localName]({});
    assert.equal(first.action.method, path);
    assert.equal(first.action.capability, capability);
    assert.equal(first.action.authorized, true);
    const second = await client[localName]({});
    assert.equal(second.action.authorized, false);
    assert.equal(calls, 2);
  });
}
