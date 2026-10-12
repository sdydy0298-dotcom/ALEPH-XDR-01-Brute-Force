import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {decide} from '../xdr/brute-force/decide.mjs';
import {readAlerts,projectAlert} from '../xdr/brute-force/read-alerts.mjs';
import {evaluateAccess} from '../ztna/evaluate.mjs';
import {respond} from '../xdr/brute-force/respond.mjs';

const fixture=JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json',import.meta.url),'utf8'));
const result=JSON.parse(await readFile(new URL('../xdr/brute-force/result.json',import.meta.url),'utf8'));
const at=Date.parse('2026-10-12T05:00:00.000Z');
test('upstream fixture shape and inspector line count',async()=>{
  assert.equal(fixture.schema,'aleph.xdr.fixture.v1');
  assert.equal(fixture.moduleKey,'brute-force');
  assert.equal(fixture.alerts.length,28);
  const records=await readAlerts();
  assert.equal(records.length,28);
  assert.equal(records[0].account,'user01');
  const check=spawnSync(process.execPath,['xdr/brute-force/read-alerts.mjs'],{encoding:'utf8'});
  assert.equal(check.status,0,check.stderr);
  assert.equal(check.stdout.trim().split('\n').length,28);
  const masked=projectAlert({rule:{description:'password=hiddenvalue token=hiddenkey'},data:{srcuser:'Bearer concealed'}});
  assert.doesNotMatch(JSON.stringify(masked),/hiddenvalue|hiddenkey|concealed/);
});
test('official result contract and matching decisions',()=>{
  assert.equal(result.schema,'aleph.xdr.result.v1');
  assert.equal(result.moduleKey,'brute-force');
  assert.equal(result.decisions.length,fixture.alerts.length);
  const counts={block:0,alert:0,record:0};
  fixture.alerts.forEach((event,i)=>{
    const actual=decide(event);
    const saved=result.decisions[i];
    assert.equal(saved.alertId,event.id);
    assert.deepEqual(saved,{alertId:event.id,...actual});
    assert.ok(typeof saved.reason==='string' && saved.reason && !/[\r\n]/.test(saved.reason));
    assert.ok(typeof saved.confidence==='number'&&saved.confidence>=0&&saved.confidence<=1);
    assert.equal(saved.action,saved.confidence>=.85?'block':saved.confidence>=.5?'alert':'record');
    counts[saved.action]++;
  });
  assert.deepEqual(counts,{block:10,alert:9,record:9});
  assert.deepEqual(result.counts,counts);
});
test('T1110 correlated clear, ambiguous and benign events',()=>{
  fixture.alerts.forEach(alert=>{
    const action=decide(alert).action;
    const t1110=alert.rule.mitre.includes('T1110');
    if(t1110 && alert.rule.level>=10)assert.equal(action,'block',alert.id);
    else if(t1110)assert.equal(action,'alert',alert.id);
    else assert.equal(action,'record',alert.id);
  });
});
test('judge single-file does not import or access outside resources',async()=>{
  const text=await readFile(new URL('../xdr/brute-force/decide.mjs',import.meta.url),'utf8');
  assert.doesNotMatch(text,/^\s*import(?:\s|[{*"'(])/m);
  assert.doesNotMatch(text,/\b(?:require|readFile|writeFile|fetch)\s*\(/);
});
test('block candidates expire; ambiguous and normal sources remain allowed',async()=>{
  const rules=JSON.parse(await readFile(new URL('../xdr/temporary-deny.json',import.meta.url),'utf8'));
  const lines=(await readFile(new URL('../xdr/alerts.log',import.meta.url),'utf8')).trim().split('\n');
  assert.equal(rules.length,10);
  assert.equal(lines.length,19);
  for(const event of fixture.alerts){
    const action=decide(event).action;
    const live=await evaluateAccess(event.data.srcip,at);
    if(action==='block'){
      assert.equal(live.action,'deny',event.id);
      assert.equal((await evaluateAccess(event.data.srcip,at+16*60*1000)).action,'allow',event.id);
    } else assert.equal(live.action,'allow',event.id);
  }
});
test('forged block verdict for benign event cannot create deny rule',async()=>{
  const benign=fixture.alerts.find(x=>!x.rule.mitre.length);
  const r=await respond(benign,{action:'block',confidence:.99,reason:'fake'},{now:new Date(at),persist:false});
  assert.equal(r.rules.length,0);
});
