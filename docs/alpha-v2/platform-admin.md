# Platform administration authorization checks

`PlatformAdminService` is a planned Weft service with four read-only, safe-retry
unary checks. Each accepts an empty `PlatformAuthorizationRequest` and returns
`PlatformAuthorizationResponse.action`, an `ActionAvailability` for that exact
method and observing credential.

| RPC | Matching semantic capability |
| --- | --- |
| `AuthorizeEmailTemplates` | `CAPABILITY_PLATFORM_EMAIL_TEMPLATES` (6) |
| `AuthorizeEmailDelivery` | `CAPABILITY_PLATFORM_EMAIL_DELIVERY` (7) |
| `AuthorizeAnalytics` | `CAPABILITY_PLATFORM_ANALYTICS` (8) |
| `AuthorizeInvitationDirectory` | `CAPABILITY_PLATFORM_INVITATION_DIRECTORY` (9) |

All checks require an authenticated principal, request proof of possession,
global-administrator standing from caller grants, and existence hiding. Their
contract area is `CAPABILITY_AREA_PLATFORM_ADMINISTRATION` (17). Authorization
comes only from current durable platform staff standing for a directly
authenticated human across supported rooting tiers. Delegated, agent, service
and anonymous credentials are denied. Verified credential/delegation attribution
establishes directness; claimed UUIDs, token staff facts and member-held actions
cannot establish staff standing. Uncertain, expired or revoked standing denies.
The producer uses the same predicate for projection and execution, verifying the
original credential, PoP and every attenuation block for the exact check method.

`PrincipalRecord.actions` projects each check with its matching capability,
exact `/heddle.api.v1alpha2.PlatformAdminService/Authorize…` method, serving Weft
endpoint, and no customer-resource target. `implemented` reflects advertised
handlers. Denied principals receive `authorized=false` advice; executed checks
deny unauthorized callers and return matching `authorized=true` advice only on
success. ObserveIdentity reprojects on standing changes or expiry, including
FOLLOW replacement/reset. Login responses may remain sparse.

Presentation requires a known matching capability, endpoint and method,
`implemented=true`, `authorized=true`, and no unmet requirements. Missing or
unknown advice denies. A Staff label may appear when any known platform action
meets these conditions; links are filtered individually.

Clients must call the matching check within **each request**, before any side
effect. A response is a point-in-time online decision for this RPC and observing
credential only, never a portable grant, bearer, offline proof or reusable
permit. No positive result persists across requests. The small interval between
the check and Cloudflare/D1 execution is accepted; those systems do not share a
Weft transaction.

Email templates/settings use EmailTemplates; test delivery and delivery audit
use EmailDelivery. Email remains in Cloudflare/D1. Analytics and the invitation
directory remain closed pending separate data/command designs. These checks do
not implement those operations, staff management, or a reusable staff boolean.

Rust clients use `heddle_api::v2::rpc::PlatformAdminServiceAuthorize…` with
`Client::call`. TypeScript exports `PlatformAdminService` and both message schemas
from `@heddleco/api/v2`; use `createServiceClient` with the authenticated endpoint's
advertised handler set. Generation derives messages, service descriptors and
transport routes from the protos; compiled availability never implies support.
