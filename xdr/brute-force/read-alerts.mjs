// Inspection-only module. Never imported by decide.mjs.
import {readFile} from 'node:fs/promises';
const input = new URL('../fixtures/brute-force.json', import.meta.url);
export async function readAlerts() {
  const data = JSON.parse(await readFile(input,'utf8'));
  const alerts = Array.isArray(data) ? data : Array.isArray(data.alerts) ? data.alerts : [];
  return alerts.map(item=>({
    time: String(item.timestamp ?? ''),
    source: String(item.data?.srcip ?? item.srcip ?? ''),
    account: String(item.data?.dstuser ?? item.account ?? ''),
    level: Number(item.rule?.level ?? 0),
    description: String(item.rule?.description ?? '').replace(/(?:password|token|secret|cookie|authorization)\s*[:=]\s*\S+/ig,'[REDACTED]').slice(0,180)
  }));
}
if(process.argv[1] && import.meta.url === new URL('file://'+process.argv[1].replace(/\\/g,'/')).href) {
  const output=await readAlerts();
  for(const entry of output) console.log(JSON.stringify(entry));
  console.log('count='+output.length);
}
