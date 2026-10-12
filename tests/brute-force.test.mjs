import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {decide} from '../xdr/brute-force/decide.mjs';
import {readAlerts} from '../xdr/brute-force/read-alerts.mjs';
import {respond} from '../xdr/brute-force/respond.mjs';
import {checkAccess} from '../ztna/check.mjs';
const alerts=JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json',import.meta.url),'utf8'));
test('reader emits exactly one safe record per alert',async()=>{
 const rows=await readAlerts();
 assert.equal(rows.length,alerts.length);
 assert.ok(rows.every(r=>Object.keys(r).sort().join(',')==='account,description,level,source,time'));
});
test('classifies the full fixture and never blocks normal events',()=>{
 const counts={block:0,alert:0,record:0};
 for(const a of alerts){
   const d=decide(a);counts[d.action]++;
   assert.ok(d.confidence>=0&&d.confidence<=1);
   assert.equal(d.action,d.confidence>=.85?'block':d.confidence>=.5?'alert':'record');
   if(a.outcome==='success'||a.data.summary.failureCount<=2)assert.notEqual(d.action,'block');
 }
 assert.deepEqual(counts,{block:4,alert:3,record:7});
});
test('decide source has no imports',async()=>{
 const code=await readFile(new URL('../xdr/brute-force/decide.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(code,/\bimport\s*(?:\(|{|[a-z"'*])/i);
});
test('temporary blocking expires; normal source stays allowed',async()=>{
 const now=new Date('2026-10-12T05:00:00.000Z');
 const hostile=alerts[0];
 const output=await respond(hostile,decide(hostile),{now,persist:false});
 assert.equal(output.rules.length,1);
 const rule=output.rules[0];
 assert.equal(rule.alertId,hostile.id);
 assert.equal(checkAccess(hostile.data.srcip,output.rules,now.getTime()).action,'deny');
 assert.equal(checkAccess(hostile.data.srcip,output.rules,now.getTime()+16*60_000).action,'allow');
 assert.equal(checkAccess('192.0.2.10',output.rules,now.getTime()).action,'allow');
});
