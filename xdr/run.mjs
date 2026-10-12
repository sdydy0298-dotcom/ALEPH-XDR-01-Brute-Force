import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {decide} from './brute-force/decide.mjs';
import {respond} from './brute-force/respond.mjs';
const operation=process.argv[2];
if(operation!=='brute-force'){console.error('Usage: npm run xdr:run -- brute-force');process.exit(1);}
const fixture=JSON.parse(await readFile(new URL('./fixtures/brute-force.json',import.meta.url),'utf8'));
const events=Array.isArray(fixture)?fixture:fixture.alerts;
if(!Array.isArray(events))throw new Error('Invalid fixture format');
const counts={block:0,alert:0,record:0};
let falseBlocks=0;
const results=[];
const base=new Date('2026-10-12T05:00:00.000Z');
const activeRules=[];
for(const item of events){
 const decision=decide(item);
 counts[decision.action]++;
 // Persist false: generate policy candidates without mutating live access state.
 const response=await respond(item,decision,{now:base,persist:false});
 for(const r of response.rules){if(!activeRules.some(x=>x.id===r.id))activeRules.push(r);}
 const expectedNormal=item.outcome==='success'||item.data?.authentication?.status==='success'||(item.data?.summary?.failureCount??0)<=2;
 if(expectedNormal&&decision.action==='block')falseBlocks++;
 results.push({alertId:item.id,action:decision.action,confidence:decision.confidence,reason:decision.reason,source:item.data?.srcip,normal:expectedNormal});
}
const report={scenario:'brute-force',generatedAt:base.toISOString(),fixtureCount:events.length,counts,normalBlocked:falseBlocks,temporaryDenyRules:activeRules,results};
const target=new URL('./brute-force/result.json',import.meta.url);
await mkdir(dirname(fileURLToPath(target)),{recursive:true});
await writeFile(target,JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({counts,normalBlocked:falseBlocks,total:events.length}));
if(falseBlocks!==0)process.exitCode=1;
