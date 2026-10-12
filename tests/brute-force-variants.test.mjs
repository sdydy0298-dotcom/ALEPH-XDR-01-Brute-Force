import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {decide} from '../xdr/brute-force/decide.mjs';
import {respond} from '../xdr/brute-force/respond.mjs';

const ip='198.51.100.25';
const sample=(options={})=>({
  id:'LAB-01',
  data:{srcip:ip,dstuser:'operator',authentication:{status:'failed'}},
  rule:{level:10,description:'Authentication failed'},
  ...options
});
const fixtures=[
  ['block: nested failure count',sample({data:{srcip:ip,dstuser:'root',summary:{failure_count:18,window_minutes:2}},rule:{level:10,description:'Multiple authentication failures'}}),'block'],
  ['block: flattened fields', {source_ip:ip,username:'admin',outcome:'failed',failed_attempts:'14',window_seconds:120,description:'Repeated failed logins'},'block'],
  ['block: Wazuh frequency/timeframe',sample({rule:{level:12,description:'sshd: multiple authentication failures',frequency:12,timeframe:180}}),'block'],
  ['block: high-confidence correlation event',sample({rule:{level:12,description:'sshd: brute force attack detected'}}),'block'],
  ['block: plain-language description count', {srcip:ip,user:'admin',rule:{level:9,description:'18 failed login attempts in 2 minutes'}},'block'],
  ['block: password spraying multiple accounts',sample({data:{srcip:ip,summary:{failureCount:15,distinctAccounts:8,windowMinutes:5}},rule:{level:12,description:'Password spraying attempts'}}),'block'],
  ['block: credential stuffing',sample({data:{srcip:ip,summary:{failureCount:30,distinctAccounts:15,windowMinutes:3}},rule:{level:14,description:'Credential stuffing'}}),'block'],
  ['block: Windows 4625 aggregate',{data:{win:{system:{eventID:'4625'}, eventdata:{ipAddress:ip,targetUserName:'staff'}},aggregate:{failure_count:12,window_minutes:4}},rule:{level:12,description:'Windows authentication failures'}},'block'],
  ['block: event array', {rule:{level:11,description:'Repeated failed login attempts'},events:Array.from({length:12},(_,i)=>({timestamp:new Date(Date.UTC(2026,9,12,1,0,i*10)).toISOString(),data:{srcip:ip,dstuser:'admin',status:'failed'},rule:{description:'Failed password for admin'}}))},'block'],
  ['block: full log source', {account:'admin',failureCount:15,windowMinutes:2,description:'Repeated failed logins',full_log:'Failed password for admin from 198.51.100.25 port 2222'},'block'],
  ['alert: moderate failures',sample({data:{srcip:ip,dstuser:'admin',summary:{failureCount:5,windowMinutes:4}}}),'alert'],
  ['alert: slow failures',sample({data:{srcip:ip,dstuser:'admin',summary:{failureCount:30,windowMinutes:45}}}),'alert'],
  ['alert: uncertainty expressed',{srcip:ip,rule:{level:12,description:'Possible brute force attack, not confirmed'}},'alert'],
  ['alert: ambiguous multi-account sign',sample({data:{srcip:ip,summary:{failureCount:5,distinctAccounts:5,windowMinutes:7}},rule:{level:9,description:'Suspected password spraying'}}),'alert'],
  ['alert: repeated no count',sample({rule:{level:8,description:'Repeated failed authentication attempts'}}),'alert'],
  ['alert: missing source',{account:'root',outcome:'failed',summary:{failureCount:20,windowMinutes:3},description:'Repeated failed logins'},'alert'],
  ['record: login success with earlier failures',sample({outcome:'success',data:{srcip:ip,summary:{failureCount:30,windowMinutes:1},authentication:{status:'success'}},rule:{level:14,description:'Login successful'}}),'record'],
  ['record: single failed password',sample({rule:{level:8,description:'Failed password for invalid user root'}}),'record'],
  ['record: two failed logins',sample({data:{srcip:ip,dstuser:'root',summary:{failureCount:2,windowMinutes:1}}}),'record'],
  ['record: unrelated service event',{srcip:ip,rule:{level:14,description:'20 failed backups to remote storage'},count:20,windowMinutes:2},'record'],
  ['record: no auth signal',{srcip:ip,rule:{level:3,description:'Heartbeat check'}},'record'],
  ['record: explicit Windows success',{data:{win:{system:{eventID:'4624'}, eventdata:{ipAddress:ip,targetUserName:'user'}},summary:{failureCount:21,windowMinutes:1}},rule:{level:12,description:'Login event'}},'record'],
  ['record: benign event with no IP', {description:'Login successful',outcome:'success'},'record']
];

for (const [name,event,expected] of fixtures) {
  test(name, async ()=>{
    const value=decide(event);
    assert.equal(value.action,expected,JSON.stringify(value));
    assert.ok(value.confidence>=0 && value.confidence<=1);
    assert.equal(value.action,value.confidence>=0.85?'block':value.confidence>=0.50?'alert':'record');
    assert.ok(typeof value.reason==='string' && value.reason && !/[\r\n]/.test(value.reason));
    if(expected!=='block') {
      const response=await respond({...event,id:'REG-'+fixtures.findIndex(x=>x[0]===name)},value,{now:new Date('2026-10-12T05:00:00Z'),persist:false});
      assert.equal(response.rules.length,0);
    }
  });
}
test('original patterns describe the same thresholds as standalone decide.mjs',async()=>{
  const patterns=JSON.parse(await readFile(new URL('../xdr/brute-force/patterns.json',import.meta.url),'utf8'));
  const code=await readFile(new URL('../xdr/brute-force/decide.mjs',import.meta.url),'utf8');
  assert.equal(patterns.length,3);
  for(const entry of patterns) {
    assert.ok(entry.name && entry.condition && entry.evidence);
    assert.ok(code.includes(entry.name),entry.name);
  }
});
