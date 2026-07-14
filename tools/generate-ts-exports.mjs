import { copyFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const root = join("build", "typescript", "heddle", "api", "v1alpha1");
const modules = readdirSync(root)
  .filter((name) => name.endsWith("_pb.ts"))
  .sort();
const lines = modules.map((name) => `export * from "./${name.replace(/\.ts$/, ".js")}";`);
copyFileSync("packages/typescript/runtime/signing.ts", join(root, "signing.ts"));
lines.push('export * from "./signing.js";');
writeFileSync(join(root, "index.ts"), `${lines.join("\n")}\n`);
writeFileSync(
  join(root, "shared.ts"),
  ["contract_pb", "errors_pb", "types_pb"].map((name) => `export * from "./${name}.js";`).join("\n") + '\nexport * from "./signing.js";\n',
);
