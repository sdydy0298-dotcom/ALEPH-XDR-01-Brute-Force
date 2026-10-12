import {readFile, writeFile, mkdir} from 'node:fs/promises';
import {dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {decide} from './brute-force/decide.mjs';
import {respond} from './brute-force/respond.mjs';
import {evaluateAccess} from '../ztna/evaluate.mjs';

if (process.argv[2] !== 'brute-force') {
  console.error('Usage: npm run xdr:run -- brute-force');
  process.exit(1);
}
const fixture = JSON.parse(await readFile(new URL('./fixtures/brute-force.json', import.meta.url), 'utf8'));
const events = Array.isArray(fixture) ? fixture : fixture.alerts;
if (!Array.isArray(events)) throw new Error('Invalid fixture format');

// Deterministic REPLAY clock (not real-world time). Re-running yields byte-for-byte same artifacts.
const now = new Date('2026-10-12T05:00:00.000Z');
const denyFile = new URL('./temporary-deny.json', import.meta.url);
const logFile = new URL('./alerts.log', import.meta.url);
await mkdir(dirname(fileURLToPath(denyFile)), {recursive: true});
await writeFile(denyFile, '[]\n');
await writeFile(logFile, '');

const counts = {block: 0, alert: 0, record: 0};
const results = [];
const rules = [];
for (const item of events) {
  const decision = decide(item);
  counts[decision.action]++;
  const response = await respond(item, decision, {now, persist: true});
  for (const rule of response.rules) {
    if (!rules.some(current => current.id === rule.id)) rules.push(rule);
  }
  // Missing failure count is not proof of a normal event.
  const observedCount = item.data?.summary?.failureCount ?? item.data?.failureCount ?? item.failureCount;
  const normal = item.outcome === 'success' ||
    item.data?.authentication?.status === 'success' ||
    (observedCount !== undefined && Number.isFinite(Number(observedCount)) &&
      Number(observedCount) <= 2 && Number(observedCount) >= 0 &&
      !/brute.?force|password.?spray|credential.?stuff/i.test(item.rule?.description ?? ''));
  results.push({
    alertId: item.id, action: decision.action, confidence: decision.confidence,
    reason: decision.reason, source: item.data?.srcip, normal
  });
}

// Test the FILE-BACKED ZTNA evaluator, not merely a label in the HTML dashboard.
let normalBlocked = 0;
for (const result of results) {
  const access = await evaluateAccess(result.source, now.getTime());
  if (result.normal && (result.action === 'block' || access.action === 'deny')) normalBlocked++;
  if (result.action === 'block' && access.action !== 'deny') {
    throw new Error('BLOCK decision was not added to the ZTNA deny policy: ' + result.alertId);
  }
  if (result.action === 'block' &&
      (await evaluateAccess(result.source, now.getTime() + 16 * 60 * 1000)).action !== 'allow') {
    throw new Error('Temporary XDR denial did not expire: ' + result.alertId);
  }
}
const lines = (await readFile(logFile, 'utf8')).trim().split('\n').filter(Boolean);
if (lines.length !== counts.block + counts.alert || rules.length !== counts.block) {
  throw new Error('Alert log / temporary deny rules differ from classifier counts');
}
const report = {
  scenario: 'brute-force', generatedAt: now.toISOString(), fixtureCount: events.length,
  counts, normalBlocked, temporaryDenyRules: rules, results
};
const target = new URL('./brute-force/result.json', import.meta.url);
await writeFile(target, JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({counts, normalBlocked, alertsLogged: lines.length, temporaryDenyRules: rules.length, total: events.length}));
if (normalBlocked !== 0) process.exitCode = 1;
