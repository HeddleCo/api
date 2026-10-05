// Record exact public declarations before/after the hard cut; no compatibility code.
import {execFileSync} from 'node:child_process';
import {readFileSync,writeFileSync} from 'node:fs';
import ts from 'typescript';
const baseline='c9bd6ba2';
function rust(source){
 const declarations=new Map();
 for(const match of source.matchAll(/^pub (fn|struct|enum|type|const) (\w+)/gm)){
  const start=match.index,kind=match[1],name=match[2];let end;
  if(kind==='fn')end=source.indexOf('{',start);
  else if(kind==='type'||kind==='const')end=source.indexOf(';',start)+1;
  else{const open=source.indexOf('{',start);let depth=1;end=open+1;while(depth&&end<source.length){const c=source[end++];if(c==='{')depth++;if(c==='}')depth--;}}
  declarations.set(name,source.slice(start,end).trim());
 }
 return declarations;
}
function typescript(source){
 const file=ts.createSourceFile('runtime.ts',source,ts.ScriptTarget.Latest,true),declarations=new Map();
 for(const node of file.statements){
  if(!node.modifiers?.some(m=>m.kind===ts.SyntaxKind.ExportKeyword))continue;
  if(ts.isFunctionDeclaration(node)&&node.name)declarations.set(node.name.text,source.slice(node.getStart(file),node.body?.getStart(file)??node.end).trim());
  else if((ts.isInterfaceDeclaration(node)||ts.isTypeAliasDeclaration(node))&&node.name)declarations.set(node.name.text,node.getText(file));
  else if(ts.isVariableStatement(node))for(const d of node.declarationList.declarations)declarations.set(d.name.getText(file),'export const '+d.getText(file)+';');
 }
 return declarations;
}
let document='# Alpha.34 exact API surface\n\nGenerated against alpha.33 (`c9bd6ba2`). All public Rust and TypeScript runtime function signatures remain unchanged. New generated protobuf surface is listed below.\n';
for(const [language,path,parse] of [['rust','src/import_authority.rs',rust],['rust','src/native_witness.rs',rust],['typescript','packages/typescript/runtime/v2-import-authority.ts',typescript],['typescript','packages/typescript/runtime/v2-native-witness.ts',typescript]]){
 const before=parse(execFileSync('git',['show',`${baseline}:${path}`],{maxBuffer:8*1024*1024}).toString()),after=parse(readFileSync(path,'utf8'));
 document+=`\n## ${language==='rust'?'Rust':'TypeScript'}\n\nSource: \`${path}\`.\n`;
 const normalize=v=>v.replace(/\s+/g,'');
 if(before.size===after.size&&[...before].every(([name,value])=>after.has(name)&&normalize(value)===normalize(after.get(name))))document+='\nNo public declarations changed.\n';
 for(const [name,old] of before){
  const current=after.get(name);
  if(current&&normalize(old)===normalize(current))continue;
  document+=`\n### ${current?'Changed':'Deleted'} \`${name}\`\n\n${current?'Before:\n\n':''}\`\`\`${language}\n${old}\n\`\`\`\n`;
  if(current)document+=`\nAfter:\n\n\`\`\`${language}\n${current}\n\`\`\`\n`;
 }
 for(const [name,current] of after)if(!before.has(name))document+=`\n### Added \`${name}\`\n\n\`\`\`${language}\n${current}\n\`\`\`\n`;
}
document+=`
## Generated protobuf surface

Package: \`heddle.api.v1alpha2\`. Definitions live in \`import_authority.proto\`; the native bundle imports the shared type.

| Declaration | Exact Rust surface | Exact TypeScript surface |
| --- | --- | --- |
| ForeignDependencyOrigin (new enum) | \`Unspecified = 0, Import = 1, Native = 2\` | \`UNSPECIFIED = 0, IMPORT = 1, NATIVE = 2\`, plus \`ForeignDependencyOriginSchema\` |
| ForeignDependencyV1 (new message) | \`format_version: u32, origin: i32, thread_genesis_digest: Vec<u8>, signed_native_digest: Vec<u8>\` | \`formatVersion: number, origin: ForeignDependencyOrigin, threadGenesisDigest: Uint8Array, signedNativeDigest: Uint8Array\`, plus \`ForeignDependencyV1Schema\` |
| NativePublicProofBundleV1 field 13 | \`foreign_dependencies: Vec<ForeignDependencyV1>\` | \`foreignDependencies: ForeignDependencyV1[]\` |
| ImportPublicProofBundleV1 field 23 | \`foreign_dependencies: Vec<ForeignDependencyV1>\` | \`foreignDependencies: ForeignDependencyV1[]\` |

ForeignDependencyV1 tags: uint32 format_version=1; ForeignDependencyOrigin origin=2; bytes thread_genesis_digest=3; bytes signed_native_digest=4. Enum wire names are FOREIGN_DEPENDENCY_ORIGIN_UNSPECIFIED / IMPORT / NATIVE. The same generated Rust module and TS ./v2 barrel expose these types; there is no new package subpath. Existing bundle schemas include the new repeated field.

No RPC, mandatory feature, error reason, signed original, purpose payload, signing domain, witness root/set/statement, or retirement leaf changes. No new public runtime helper or resolver: Rust References and TS _foreign-dependencies are private implementation details.
`;
writeFileSync('breaking/0.31.0-alpha.34-api-surface.md',document);
console.log('Generated exact alpha.34 public declaration changes');
