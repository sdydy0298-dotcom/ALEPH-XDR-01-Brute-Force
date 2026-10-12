import {readFile} from 'node:fs/promises';
import {isIP} from 'node:net';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

const input = new URL('../fixtures/brute-force.json', import.meta.url);
function redact(value) {
  return String(value ?? '').replace(/[\r\n\t]/g, ' ')
    .replace(/\b(?:password|passwd|pwd|token|secret|cookie|authorization|api[_-]?key)\b\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s&,;]+)/gi, '[REDACTED]')
    .replace(/\bBearer\s+[^\s&,;]+/gi, 'Bearer [REDACTED]')
    .replace(/\b[A-Za-z0-9_-]{48,}\b/g, '[REDACTED]')
    .slice(0, 180);
}
export function projectAlert(item) {
  const source = String(item?.data?.srcip ?? item?.data?.src_ip ?? item?.data?.source_ip ?? item?.srcip ?? item?.source_ip ?? item?.source?.ip ?? item?.data?.win?.eventdata?.ipAddress ?? '');
  const lvl = Number(item?.rule?.level ?? 0);
  return {
    time: redact(item?.timestamp),
    source: isIP(source) ? source : '',
    account: redact(item?.data?.dstuser ?? item?.data?.username ?? item?.data?.user ?? item?.account ?? item?.username ?? item?.data?.win?.eventdata?.targetUserName),
    level: Number.isFinite(lvl) ? lvl : 0,
    description: redact(item?.rule?.description)
  };
}
export async function readAlerts() {
  const data = JSON.parse(await readFile(input, 'utf8'));
  const alerts = Array.isArray(data) ? data : Array.isArray(data.alerts) ? data.alerts : [];
  return alerts.map(projectAlert);
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  // Exactly one JSON line per input record; no count/secret payload on stdout.
  for (const entry of await readAlerts()) console.log(JSON.stringify(entry));
}
