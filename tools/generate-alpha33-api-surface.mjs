// Record exact public declarations before/after the hard cut; no compatibility code.
import {execFileSync} from 'node:child_process';
import {readFileSync,writeFileSync} from 'node:fs';
import ts from 'typescript';
const baseline='77f73219';
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
let document='# Alpha.33 exact Rust and TypeScript API changes\n\nGenerated against alpha.32 (`77f73219`) from public declarations. Unchanged APIs, including Retry and Cancel signatures, are omitted. Generated protobuf changes are listed in [the breaking notice](0.31.0-alpha.33.md).\n';
for(const [language,path,parse] of [['rust','src/import_authority.rs',rust],['typescript','packages/typescript/runtime/v2-import-authority.ts',typescript]]){
 const before=parse(execFileSync('git',['show',`${baseline}:${path}`],{maxBuffer:8*1024*1024}).toString()),after=parse(readFileSync(path,'utf8'));
 document+=`\n## ${language==='rust'?'Rust':'TypeScript'}\n\nSource: \`${path}\`.\n`;
 const normalize=v=>v.replace(/\s+/g,'');
 for(const [name,old] of before){
  const current=after.get(name);
  if(current&&normalize(old)===normalize(current))continue;
  document+=`\n### ${current?'Changed':'Deleted'} \`${name}\`\n\n${current?'Before:\n\n':''}\`\`\`${language}\n${old}\n\`\`\`\n`;
  if(current)document+=`\nAfter:\n\n\`\`\`${language}\n${current}\n\`\`\`\n`;
 }
 for(const [name,current] of after)if(!before.has(name))document+=`\n### Added \`${name}\`\n\n\`\`\`${language}\n${current}\n\`\`\`\n`;
}
writeFileSync('breaking/0.31.0-alpha.33-api-surface.md',document);
console.log('Generated exact alpha.33 public declaration changes');
