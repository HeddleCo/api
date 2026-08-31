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
