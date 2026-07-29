// Copy this file to the root of a pinned Tapestry checkout before bundling.
// The bundle exposes only the owner-authorization surface used by conformance.
export * as capability from "./src/lib/owner-authorization/capability.ts";
export * as canonical from "./src/lib/owner-authorization/canonical.ts";
export * as cryptoModule from "./src/lib/owner-authorization/crypto.ts";
export * as recovery from "./src/lib/owner-authorization/recovery.ts";
export * as rootModule from "./src/lib/owner-authorization/root.ts";
export * as types from "./src/lib/owner-authorization/types.ts";
export * as wire from "./src/lib/owner-authorization/wire.ts";
export { verificationLimits } from "./src/lib/owner-authorization/limits.ts";
