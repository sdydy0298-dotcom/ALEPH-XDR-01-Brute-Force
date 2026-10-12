import {readFile, writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {runXdr} from '../scripts/xdr-run.mjs';
import {respond} from './brute-force/respond.mjs';
import {evaluateAccess} from '../ztna/evaluate.mjs';

const moduleKey=process.argv[2];
if(moduleKey!=='brute-force') {
  console.error('Usage: npm run xdr:run -- brute-force');
  process.exit(1);
}
const root=fileURLToPath(new URL('../',import.meta.url));
const input=new URL('./fixtures/brute-force.json',import.meta.url);
const fixture=JSON.parse(await readFile(input,'utf8'));
const clock=new Date('2026-10-12T05:00:00.000Z');

// Run the canonical upstream offline judge runner without modifying its output.
const report=await runXdr({root,moduleKey});
const denyFile=new URL('./temporary-deny.json',import.meta.url);
const logFile=new URL('./alerts.log',import.meta.url);
await writeFile(denyFile,'[]\n');
await writeFile(logFile,'');

for(let i=0;i<fixture.alerts.length;i++) {
  const event=fixture.alerts[i];
  const decision=report.decisions[i];
  if(event.id!==decision.alertId)throw new Error('Fixture/result ID mismatch');
  await respond(event,decision,{now:clock,persist:true});
}
const stored=JSON.parse(await readFile(denyFile,'utf8'));
const alerts=(await readFile(logFile,'utf8')).trim().split('\n').filter(Boolean);
const clear=report.decisions.filter(x=>x.action==='block');
const ambiguous=report.decisions.filter(x=>x.action==='alert');
if(stored.length!==clear.length)throw new Error('Temporary denial count mismatch');
if(alerts.length!==clear.length+ambiguous.length)throw new Error('Alert notification count mismatch');
let normalBlocked=0;
for(let i=0;i<fixture.alerts.length;i++) {
  const event=fixture.alerts[i];
  const baselineNormal=!event.rule.mitre?.includes('T1110') && Number(event.rule.level)<=3;
  const actual=await evaluateAccess(event.data.srcip,clock.getTime());
  if(baselineNormal && (report.decisions[i].action==='block' || actual.action==='deny'))normalBlocked++;
}
if(normalBlocked)throw new Error('Normal event was blocked');
console.log(JSON.stringify({schema:report.schema,counts:report.counts,normalBlocked,alertsLogged:alerts.length,temporaryDenyRules:stored.length,total:fixture.alerts.length}));
