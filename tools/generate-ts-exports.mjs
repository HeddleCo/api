import { copyFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const apiRoot = join("build", "typescript", "heddle", "api");
const commonRoot = join(apiRoot, "common");
const v2Root = join(apiRoot, "v1alpha2");

function exportStar(dir, extra = []) {
  const modules = readdirSync(dir)
    .filter((name) => name.endsWith("_pb.ts"))
    .sort();
  const lines = modules.map((name) => `export * from "./${name.replace(/\.ts$/, ".js")}";`);
  lines.push(...extra);
  writeFileSync(join(dir, "index.ts"), `${lines.join("\n")}\n`);
}

copyFileSync("packages/typescript/runtime/errors.ts", join(commonRoot, "errors.ts"));
copyFileSync("packages/typescript/runtime/signing.ts", join(commonRoot, "signing.ts"));
copyFileSync("packages/typescript/runtime/treadle.ts", join(commonRoot, "treadle.ts"));
copyFileSync("packages/typescript/runtime/treadle-authoring.ts", join(commonRoot, "treadle-authoring.ts"));
copyFileSync("packages/typescript/runtime/framing.ts", join(commonRoot, "framing.ts"));
writeFileSync(
  join(commonRoot, "shared.ts"),
  ["contract_pb", "errors_pb", "types_pb"]
    .map((name) => `export * from "./${name}.js";`)
    .join("\n") + '\nexport * from "./errors.js";\nexport * from "./signing.js";\n',
);
exportStar(commonRoot, [
  'export * from "./errors.js";',
  'export * from "./signing.js";',
  'export * from "./treadle.js";',
  'export * from "./treadle-authoring.js";',
  'export * from "./framing.js";',
  'export * from "./attachment-authorization.js";',
]);

for (const name of readdirSync(commonRoot).filter((name) => name.endsWith(".ts"))) {
  writeFileSync(
    join(apiRoot, name),
    `export * from "./common/${name.replace(/\.ts$/, ".js")}";\n`,
  );
}

copyFileSync("packages/typescript/runtime/v2-observation.ts", join(v2Root, "observation.ts"));
copyFileSync("packages/typescript/runtime/v2-client.ts", join(v2Root, "client.ts"));
copyFileSync("packages/typescript/runtime/v2-owner-certificates.ts", join(v2Root, "owner-certificates.ts"));
copyFileSync("packages/typescript/runtime/v2-password-owner.ts", join(v2Root, "password-owner.ts"));
copyFileSync("packages/typescript/runtime/v2-mint-root-association.ts", join(v2Root, "mint-root-association.ts"));
copyFileSync("packages/typescript/runtime/v2-spool-creation.ts", join(v2Root, "spool-creation.ts"));
copyFileSync("packages/typescript/runtime/v2-owner-actions.ts", join(v2Root, "owner-actions.ts"));
copyFileSync("packages/typescript/runtime/v2-provider.ts", join(v2Root, "provider.ts"));
copyFileSync("packages/typescript/runtime/v2-pairing.ts", join(v2Root, "pairing.ts"));
copyFileSync("packages/typescript/runtime/v2-thread-control.ts", join(v2Root, "thread-control.ts"));
copyFileSync("packages/typescript/runtime/v2-thread-genesis.ts", join(v2Root, "thread-genesis.ts"));
copyFileSync("packages/typescript/runtime/v2-thread-ownership.ts", join(v2Root, "thread-ownership.ts"));
copyFileSync("packages/typescript/runtime/v2-evidence.ts", join(v2Root, "evidence.ts"));
copyFileSync("packages/typescript/runtime/v2-initial-source.ts", join(v2Root, "initial-source.ts"));
copyFileSync("packages/typescript/runtime/v2-collaboration.ts", join(v2Root, "collaboration.ts"));
copyFileSync("packages/typescript/runtime/v2-source-targets.ts", join(v2Root, "source-targets.ts"));
copyFileSync("packages/typescript/runtime/v2-invitation.ts", join(v2Root, "invitation.ts"));
copyFileSync("packages/typescript/runtime/v2-msgpack.ts", join(v2Root, "_collaboration-msgpack.ts"));
const v2Modules = readdirSync(v2Root)
  .filter((name) => name.endsWith(".ts") && name !== "index.ts" && !name.startsWith("_"))
  .sort();
writeFileSync(
  join(v2Root, "index.ts"),
  v2Modules.map((name) => `export * from "./${name.replace(/\.ts$/, ".js")}";`).join("\n") + "\n",
);
