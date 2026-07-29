import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const NOW = 1_000n;
const LIMIT_SECONDS = 3_600n;
const DEFAULT_SEED = 0x248c0de;
const GRAPH_COUNT = Number(process.env.OWNER_AUTH_GRAPH_COUNT ?? "24");
const profile = process.env.OWNER_AUTH_PROFILE ?? "current";
const verifier = process.env.HEDDLE_VERIFIER_BIN;
const scratch = process.env.OWNER_AUTH_SCRATCH;

if (!["current", "pre-fix"].includes(profile)) {
  throw new Error(`unknown OWNER_AUTH_PROFILE: ${profile}`);
}
if (!verifier || !scratch) {
  throw new Error(
    "HEDDLE_VERIFIER_BIN and OWNER_AUTH_SCRATCH are required",
  );
}

const bridgeUrl = (selectedProfile: string) =>
  pathToFileURL(
    path.join(
      import.meta.dir,
      "artifacts",
      `${selectedProfile}-tapestry.mjs`,
    ),
  ).href;

// Corpus construction is always pinned to the current bridge. Only verification
// switches profiles, so the historical replay consumes byte-identical chains.
const generator = await import(bridgeUrl("current"));
const tapestryVerifier = await import(bridgeUrl(profile));
const capability = generator.capability;
const canonical = generator.canonical;
const cryptoModule = generator.cryptoModule;
const recovery = generator.recovery;
const rootModule = generator.rootModule;
const types = generator.types;
const wire = generator.wire;
const limits = generator.verificationLimits(
  300n,
  LIMIT_SECONDS,
  1024 * 1024,
);

const Action = types.SpoolCapabilityAction;
const Principal = types.CapabilityPrincipalKind;
const actions = [
  Action.Read,
  Action.Write,
  Action.Merge,
  Action.Approve,
  Action.Admin,
  Action.Redact,
  Action.Grant,
  Action.Purge,
];

type Selector = {
  rootSpoolUuid: Uint8Array;
  pathSegments: string[];
  includeDescendants: boolean;
};

type Grant = {
  spool: Selector;
  actions: number[];
};

type SignedCapability = {
  capability?: {
    ownerId: Uint8Array;
    issuerStateHash: Uint8Array;
    capabilityId: Uint8Array;
    subject?: { key?: unknown };
    grants: Grant[];
    notBeforeUnixSeconds: bigint;
    expiresAtUnixSeconds: bigint;
  };
  signature?: unknown;
};

type Case = {
  id: string;
  boundary: string;
  expected: boolean;
  chain_hex: string[];
};

class Random {
  constructor(private state: number) {}

  next(): number {
    let value = (this.state += 0x6d2b79f5);
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 0x1_0000_0000;
  }

  int(ceiling: number): number {
    return Math.floor(this.next() * ceiling);
  }

  bool(): boolean {
    return this.next() < 0.5;
  }

  bytes(length: number): Uint8Array {
    return Uint8Array.from({ length }, () => this.int(256));
  }
}

const seed = Number(process.env.OWNER_AUTH_CASE_SEED ?? DEFAULT_SEED);
const random = new Random(seed);
let keySequence = 1;

async function key() {
  const bytes = new Uint8Array(32);
  new DataView(bytes.buffer).setUint32(28, keySequence++, false);
  return cryptoModule.__ownerAuthorizationCryptoTest.importSeed(bytes);
}

function subject(signingKey: {
  verificationKey: unknown;
}): { kind: number; principalId: Uint8Array; key: unknown } {
  return {
    kind: Principal.Agent,
    principalId: new TextEncoder().encode(`fuzz-agent-${keySequence}`),
    key: signingKey.verificationKey,
  };
}

function cloneSelector(selector: Selector): Selector {
  return {
    rootSpoolUuid: selector.rootSpoolUuid.slice(),
    pathSegments: [...selector.pathSegments],
    includeDescendants: selector.includeDescendants,
  };
}

function selectorCovers(parent: Selector, child: Selector): boolean {
  if (
    !wire.bytesEqual(parent.rootSpoolUuid, child.rootSpoolUuid) ||
    (!parent.includeDescendants && child.includeDescendants)
  ) {
    return false;
  }
  if (!parent.includeDescendants) {
    return (
      parent.pathSegments.length === child.pathSegments.length &&
      parent.pathSegments.every(
        (segment, index) => segment === child.pathSegments[index],
      )
    );
  }
  return parent.pathSegments.every(
    (segment, index) => segment === child.pathSegments[index],
  );
}

function assertionIsGranted(parent: Grant[], child: Grant[]): boolean {
  if (child.some((grant) => grant.actions.includes(Action.Purge))) {
    return false;
  }
  return child.every((assertion) =>
    parent.some((grant) => {
      const granted = new Set(grant.actions);
      return (
        granted.has(Action.Grant) &&
        assertion.actions.every((action) => granted.has(action)) &&
        selectorCovers(grant.spool, assertion.spool)
      );
    }),
  );
}

async function rawChild(
  parent: SignedCapability,
  signer: unknown,
  childSubject: unknown,
  grants: Grant[],
): Promise<SignedCapability> {
  const body = parent.capability;
  if (!body) throw new Error("parent capability has no body");
  const value = {
    formatVersion: 1,
    ownerId: body.ownerId.slice(),
    issuerStateHash: body.issuerStateHash.slice(),
    parentCapabilityId: body.capabilityId.slice(),
    subject: childSubject,
    grants,
    notBeforeUnixSeconds: body.notBeforeUnixSeconds,
    expiresAtUnixSeconds: body.expiresAtUnixSeconds,
    nonce: random.bytes(32),
    capabilityId: new Uint8Array(32),
  };
  value.capabilityId = await canonical.digest(
    canonical.OWNER_CAPABILITY_DOMAIN,
    await canonical.capabilityWithoutId(value),
  );
  return {
    capability: value,
    signature: await cryptoModule.signCanonical(
      signer,
      canonical.OWNER_CAPABILITY_DOMAIN,
      await canonical.capabilityBody(value),
    ),
  };
}

function encodedChain(chain: SignedCapability[]): string[] {
  return chain.map((value) =>
    Buffer.from(
      wire.ownerAuthorizationCodecs.signedOwnerCapability.encode(value),
    ).toString("hex"),
  );
}

const authority = await key();
const ownerRoot = await rootModule.createHumanOwnerRoot(
  random.bytes(16),
  authority,
  await recovery.recommendedRecovery([
    recovery.paperGuardian(await key()),
    recovery.socialGuardian(await key()),
  ]),
);
const state = await rootModule.verifyOwnerRoot(ownerRoot);
const tapestryState =
  await tapestryVerifier.rootModule.verifyOwnerRoot(ownerRoot);
const cases: Case[] = [];
const tapestryOutcomes = new Map<string, boolean>();

async function addCase(
  id: string,
  boundary: string,
  expected: boolean,
  chain: SignedCapability[],
): Promise<void> {
  let accepted = true;
  try {
    await tapestryVerifier.capability.verifyCapabilityChain(
      tapestryState,
      chain,
      NOW,
      limits,
    );
  } catch {
    accepted = false;
  }
  cases.push({ id, boundary, expected, chain_hex: encodedChain(chain) });
  tapestryOutcomes.set(id, accepted);
}

const purgeSubjectKey = await key();
const purgeSelector: Selector = {
  rootSpoolUuid: random.bytes(16),
  pathSegments: ["seeded", "purge"],
  includeDescendants: false,
};
const directPurge = await capability.createDirectCapability(
  state,
  authority,
  subject(purgeSubjectKey),
  [{ spool: purgeSelector, actions: [Action.Grant, Action.Purge] }],
  NOW - 10n,
  NOW + 200n,
  limits,
);
await addCase("authority-purge", "authority", true, [directPurge]);
const delegatedPurge = await rawChild(
  directPurge,
  purgeSubjectKey,
  subject(await key()),
  [{ spool: cloneSelector(purgeSelector), actions: [Action.Purge] }],
);
await addCase(
  "seeded-delegated-purge",
  "purge-non-delegability",
  false,
  [directPurge, delegatedPurge],
);
const adminSubjectKey = await key();
const directAdmin = await capability.createDirectCapability(
  state,
  authority,
  subject(adminSubjectKey),
  [
    {
      spool: cloneSelector(purgeSelector),
      actions: [Action.Admin, Action.Grant],
    },
  ],
  NOW - 10n,
  NOW + 200n,
  limits,
);
const adminToPurge = await rawChild(
  directAdmin,
  adminSubjectKey,
  subject(await key()),
  [{ spool: cloneSelector(purgeSelector), actions: [Action.Purge] }],
);
await addCase(
  "admin-does-not-carry-purge",
  "purge-non-inheritance",
  false,
  [directAdmin, adminToPurge],
);

for (let graph = 0; graph < GRAPH_COUNT; graph += 1) {
  const grantCount = 1 + random.int(3);
  let grants: Grant[] = Array.from({ length: grantCount }, (_, index) => {
    const selected = new Set<number>([Action.Grant]);
    while (selected.size < 2 + random.int(3)) {
      selected.add(1 + random.int(6));
    }
    return {
      spool: {
        rootSpoolUuid: random.bytes(16),
        pathSegments: [`org-${graph}`, `repo-${index}`],
        includeDescendants: random.bool(),
      },
      actions: [...selected].sort((left, right) => left - right),
    };
  });
  let signer = await key();
  let chain: SignedCapability[] = [
    await capability.createDirectCapability(
      state,
      authority,
      subject(signer),
      grants,
      NOW - 10n,
      NOW + 200n,
      limits,
    ),
  ];
  const depth = 1 + random.int(6);
  for (let level = 1; level < depth; level += 1) {
    const verified = (
      await capability.verifyCapabilityChain(state, chain, NOW, limits)
    ).at(-1);
    if (!verified) throw new Error("verified chain is empty");
    grants = grants
      .filter((_, index) => index === 0 || random.bool())
      .map((grant) => {
        const selector = cloneSelector(grant.spool);
        if (selector.includeDescendants && random.bool()) {
          selector.pathSegments.push(`depth-${level}`);
        }
        selector.includeDescendants =
          selector.includeDescendants && random.bool();
        const retained = grant.actions.filter(
          (action) => action === Action.Grant || random.bool(),
        );
        return { spool: selector, actions: retained };
      });
    const nextSigner = await key();
    chain = [
      ...chain,
      await capability.createChildCapability(
        verified,
        signer,
        subject(nextSigner),
        grants,
        NOW - 10n,
        NOW + 200n,
        limits,
      ),
    ];
    signer = nextSigner;
  }

  const granted = grants[random.int(grants.length)];
  const assertionSelector = cloneSelector(granted.spool);
  assertionSelector.includeDescendants = false;
  if (granted.spool.includeDescendants && random.bool()) {
    assertionSelector.pathSegments.push("asserted-child");
  }
  const boundaries: Array<[string, Grant[]]> = actions.map((action) => [
    `action-${action}`,
    [{ spool: cloneSelector(assertionSelector), actions: [action] }],
  ]);
  const missing = actions.find(
    (action) =>
      action !== Action.Purge && !granted.actions.includes(action),
  );
  if (missing === undefined) throw new Error("random grant has no missing action");
  const present =
    granted.actions.find((action) => action !== Action.Grant) ?? Action.Grant;
  boundaries.push(
    [
      "subset",
      [{ spool: cloneSelector(assertionSelector), actions: [present] }],
    ],
    [
      "disjoint",
      [{ spool: cloneSelector(assertionSelector), actions: [missing] }],
    ],
    [
      "superset",
      [{
        spool: cloneSelector(assertionSelector),
        actions: [present, missing].sort((left, right) => left - right),
      }],
    ],
    [
      "cross-resource",
      [{
        spool: {
          ...cloneSelector(assertionSelector),
          rootSpoolUuid: random.bytes(16),
        },
        actions: [present],
      }],
    ],
    [
      "segment-sibling",
      [{
        spool: {
          ...cloneSelector(assertionSelector),
          pathSegments: assertionSelector.pathSegments.map((segment, index) =>
            index === assertionSelector.pathSegments.length - 1
              ? `${segment}-evil`
              : segment,
          ),
        },
        actions: [present],
      }],
    ],
    [
      "ancestor",
      [{
        spool: {
          ...cloneSelector(assertionSelector),
          pathSegments: assertionSelector.pathSegments.slice(0, -1),
        },
        actions: [present],
      }],
    ],
    [
      "mixed-set",
      [
        { spool: cloneSelector(assertionSelector), actions: [present] },
        {
          spool: {
            ...cloneSelector(assertionSelector),
            rootSpoolUuid: random.bytes(16),
          },
          actions: [present],
        },
      ],
    ],
  );

  for (const [boundary, asserted] of boundaries) {
    const candidate = await rawChild(
      chain.at(-1)!,
      signer,
      subject(await key()),
      asserted,
    );
    await addCase(
      `graph-${graph}-depth-${depth}-${boundary}`,
      boundary,
      assertionIsGranted(grants, asserted),
      [...chain, candidate],
    );
  }
}

mkdirSync(scratch, { recursive: true });
const corpusPath = path.join(scratch, "owner-authorization-corpus.json");
writeFileSync(
  corpusPath,
  JSON.stringify({
    seed,
    signed_owner_root_hex: Buffer.from(
      wire.ownerAuthorizationCodecs.signedOwnerRoot.encode(ownerRoot),
    ).toString("hex"),
    cases,
  }),
);
const heddleOutcomes = JSON.parse(
  execFileSync(verifier, [corpusPath], { encoding: "utf8" }),
) as Array<{ id: string; accepted: boolean; error?: string }>;
const byId = new Map(heddleOutcomes.map((outcome) => [outcome.id, outcome]));
const divergences: string[] = [];
const violations: string[] = [];

for (const testCase of cases) {
  const tapestryAccepted = tapestryOutcomes.get(testCase.id);
  const heddle = byId.get(testCase.id);
  if (tapestryAccepted !== heddle?.accepted) {
    divergences.push(
      `${testCase.id}: tapestry=${tapestryAccepted} heddle=${
        heddle?.accepted ?? "missing"
      }`,
    );
  }
  const expectedHistoricalViolation =
    profile === "pre-fix" &&
    testCase.id === "seeded-delegated-purge" &&
    tapestryAccepted === true &&
    heddle?.accepted === true;
  if (
    !expectedHistoricalViolation &&
    (tapestryAccepted !== testCase.expected ||
      heddle?.accepted !== testCase.expected)
  ) {
    violations.push(
      `${testCase.id}: expected=${testCase.expected} tapestry=${
        tapestryAccepted ?? "missing"
      } heddle=${heddle?.accepted ?? "missing"} error=${
        heddle?.error ?? "none"
      }`,
    );
  }
}

const seeded = cases.find(
  (testCase) => testCase.id === "seeded-delegated-purge",
)!;
const seededTapestry = tapestryOutcomes.get(seeded.id);
const seededHeddle = byId.get(seeded.id)?.accepted;
if (profile === "pre-fix") {
  if (seededTapestry !== true || seededHeddle !== true) {
    throw new Error(
      `seeded replay did not reproduce: tapestry=${seededTapestry} heddle=${seededHeddle}`,
    );
  }
  console.log(
    `SEEDED_VIOLATION=CAUGHT id=${seeded.id} expected=REJECT tapestry=${
      seededTapestry ? "ACCEPT" : "REJECT"
    } heddle=${seededHeddle ? "ACCEPT" : "REJECT"}`,
  );
}
if (divergences.length > 0 || violations.length > 0) {
  throw new Error(
    [
      ...divergences.map((value) => `DIVERGENCE ${value}`),
      ...violations.map((value) => `VIOLATION ${value}`),
    ].join("\n"),
  );
}

const accepted = cases.filter((testCase) => testCase.expected).length;
const rejected = cases.length - accepted;
if (profile === "current") {
  console.log("SEEDED_VIOLATION=REJECTED_BY_BOTH id=seeded-delegated-purge");
}
console.log(
  `CROSS_CLIENT_AGREEMENT=PASS profile=${profile} seed=${seed} graphs=${GRAPH_COUNT} cases=${
    cases.length
  } accepted=${accepted} rejected=${rejected}`,
);
