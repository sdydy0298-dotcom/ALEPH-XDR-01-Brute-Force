import {readFile,writeFile,mkdir,copyFile} from 'node:fs/promises';
const fixture=JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json',import.meta.url),'utf8'));
const actual=JSON.parse(await readFile(new URL('../xdr/brute-force/result.json',import.meta.url),'utf8'));
const rules=JSON.parse(await readFile(new URL('../xdr/temporary-deny.json',import.meta.url),'utf8'));
if(actual.schema!=='aleph.xdr.result.v1' || actual.moduleKey!=='brute-force' ||
   actual.decisions.length!==fixture.alerts.length)throw new Error('Invalid XDR result for dashboard');
const results=actual.decisions.map((decision,i)=>({
  alertId:decision.alertId, action:decision.action, confidence:decision.confidence,
  reason:decision.reason, source:fixture.alerts[i].data.srcip,
  normal:!fixture.alerts[i].rule.mitre?.includes('T1110') && fixture.alerts[i].rule.level<=3
}));
const report={
  scenario:'brute-force',generatedAt:'2026-10-12T05:00:00.000Z',
  fixtureCount:fixture.alerts.length,counts:actual.counts,
  normalBlocked:results.filter(r=>r.normal && r.action==='block').length,
  temporaryDenyRules:rules,results
};
await mkdir(new URL('../public/',import.meta.url),{recursive:true});
await writeFile(new URL('../public/report.json',import.meta.url),JSON.stringify(report,null,2)+'\n');
await copyFile(new URL('../index.html',import.meta.url),new URL('../public/index.html',import.meta.url));
console.log('XDR-01 static dashboard ready');
