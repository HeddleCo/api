import { copyFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const root = join("build", "typescript", "heddle", "api", "v1alpha1");
const modules = readdirSync(root)
  .filter((name) => name.endsWith("_pb.ts"))
  .sort();
const lines = modules.map((name) => `export * from "./${name.replace(/\.ts$/, ".js")}";`);
copyFileSync("packages/typescript/runtime/errors.ts", join(root, "errors.ts"));
copyFileSync("packages/typescript/runtime/signing.ts", join(root, "signing.ts"));
copyFileSync("packages/typescript/runtime/treadle.ts", join(root, "treadle.ts"));
copyFileSync("packages/typescript/runtime/treadle-authoring.ts", join(root, "treadle-authoring.ts"));
copyFileSync("packages/typescript/runtime/framing.ts", join(root, "framing.ts"));
lines.push('export * from "./errors.js";');
lines.push('export * from "./signing.js";');
lines.push('export * from "./treadle.js";');
lines.push('export * from "./treadle-authoring.js";');
lines.push('export * from "./framing.js";');
lines.push('export * from "./attachment-authorization.js";');
writeFileSync(join(root, "index.ts"), `${lines.join("\n")}\n`);
writeFileSync(
  join(root, "shared.ts"),
  ["contract_pb", "errors_pb", "types_pb"].map((name) => `export * from "./${name}.js";`).join("\n") +
    '\nexport * from "./errors.js";\nexport * from "./signing.js";\n',
);

// Preserve every existing package/file entry point while compiling both wire
// packages from their common root. These aliases are generated, not maintained
// as a second hand-written list of v1 modules.
const apiRoot = join(root, "..");
for (const name of readdirSync(root).filter((name) => name.endsWith(".ts"))) {
  writeFileSync(join(apiRoot, name), `export * from "./v1alpha1/${name.replace(/\.ts$/, ".js")}";\n`);
}
const v2Root = join(apiRoot, "v2alpha1");
copyFileSync("packages/typescript/runtime/v2-observation.ts", join(v2Root, "observation.ts"));
copyFileSync("packages/typescript/runtime/v2-client.ts", join(v2Root, "client.ts"));
copyFileSync("packages/typescript/runtime/v2-owner-certificates.ts", join(v2Root, "owner-certificates.ts"));
copyFileSync("packages/typescript/runtime/v2-pairing.ts", join(v2Root, "pairing.ts"));
copyFileSync("packages/typescript/runtime/v2-thread-control.ts", join(v2Root, "thread-control.ts"));
copyFileSync("packages/typescript/runtime/v2-thread-ownership.ts", join(v2Root, "thread-ownership.ts"));
copyFileSync("packages/typescript/runtime/v2-evidence.ts", join(v2Root, "evidence.ts"));
copyFileSync("packages/typescript/runtime/v2-initial-source.ts", join(v2Root, "initial-source.ts"));
copyFileSync("packages/typescript/runtime/v2-collaboration.ts", join(v2Root, "collaboration.ts"));
copyFileSync("packages/typescript/runtime/v2-msgpack.ts", join(v2Root, "_collaboration-msgpack.ts"));
const v2Modules = readdirSync(v2Root).filter((name) => name.endsWith(".ts") && name !== "index.ts" && !name.startsWith("_")).sort();
writeFileSync(join(v2Root, "index.ts"), v2Modules.map((name) => `export * from "./${name.replace(/\.ts$/, ".js")}";`).join("\n") + "\n");
