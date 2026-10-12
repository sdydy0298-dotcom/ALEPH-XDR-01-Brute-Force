import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {decide} from '../xdr/brute-force/decide.mjs';
import {readAlerts, projectAlert} from '../xdr/brute-force/read-alerts.mjs';
import {respond} from '../xdr/brute-force/respond.mjs';
import {checkAccess} from '../ztna/check.mjs';
import {evaluateAccess} from '../ztna/evaluate.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8'));
const report = JSON.parse(await readFile(new URL('../xdr/brute-force/result.json', import.meta.url), 'utf8'));
const now = new Date(report.generatedAt);

test('one safe extracted record for every Wazuh alert', async () => {
  const rows = await readAlerts();
  assert.equal(rows.length, fixture.length);
  assert.ok(rows.every(row => Object.keys(row).sort().join(',') === 'account,description,level,source,time'));
  const direct = spawnSync(process.execPath, ['xdr/brute-force/read-alerts.mjs'], {encoding: 'utf8'});
  assert.equal(direct.status, 0, direct.stderr);
  assert.equal(direct.stdout.trim().split('\n').length, fixture.length);
  const secret = projectAlert({rule: {description: 'failed login password=topsecret token=abc123'}, data: {dstuser: 'Bearer hiddenvalue'}});
  assert.doesNotMatch(JSON.stringify(secret), /topsecret|abc123|hiddenvalue/);
});

test('classifications obey thresholds and protect normal events', () => {
  const counts = {block: 0, alert: 0, record: 0};
  for (const event of fixture) {
    const result = decide(event);
    counts[result.action]++;
    assert.ok(Number.isFinite(result.confidence) && result.confidence >= 0 && result.confidence <= 1);
    assert.equal(result.action, result.confidence >= 0.85 ? 'block' : result.confidence >= 0.5 ? 'alert' : 'record');
    assert.equal(result.reason.includes('\n'), false);
    if (event.outcome === 'success' || event.data.summary.failureCount <= 2) {
      assert.notEqual(result.action, 'block');
    }
  }
  assert.deepEqual(counts, {block: 4, alert: 3, record: 7});
  assert.deepEqual(report.counts, counts);
  assert.equal(report.normalBlocked, 0);
});

test('offline judge decide.mjs has no imports, file IO, or external calls', async () => {
  const code = await readFile(new URL('../xdr/brute-force/decide.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(code, /^\s*import(?:\s|[{*"'])/m);
  assert.doesNotMatch(code, /\b(?:readFile|writeFile|fetch|require)\s*\(/);
  assert.equal(typeof decide, 'function');
  assert.equal(decide({outcome: 'success', data: {srcip: '192.0.2.1'}}).action, 'record');
  assert.equal(decide({data: {srcip: '192.0.2.1'}}).action, 'record');
});

test('persisted alert notifications and temporary rules match verdicts', async () => {
  const lines = (await readFile(new URL('../xdr/alerts.log', import.meta.url), 'utf8')).trim().split('\n').filter(Boolean);
  const stored = JSON.parse(await readFile(new URL('../xdr/temporary-deny.json', import.meta.url), 'utf8'));
  assert.equal(lines.length, 7);
  assert.equal(stored.length, 4);
  for (const line of lines) {
    const item = JSON.parse(line);
    assert.ok(['block', 'alert'].includes(item.action));
    assert.ok(item.alertId && item.at && item.reason);
    assert.equal(Object.hasOwn(item, 'password'), false);
  }
  assert.deepEqual(stored, report.temporaryDenyRules);
  for (const rule of stored) {
    assert.ok(rule.alertId && rule.expiresAt && rule.source);
    assert.equal((await evaluateAccess(rule.source, now)).action, 'deny');
    assert.equal((await evaluateAccess(rule.source, now.getTime() + 16 * 60 * 1000)).action, 'allow');
  }
});

test('all normal fixture requests pass through the actual file-backed ZTNA adapter', async () => {
  for (const item of report.results.filter(x => x.normal)) {
    assert.equal((await evaluateAccess(item.source, now)).action, 'allow', item.alertId);
  }
  assert.equal(checkAccess('192.0.2.10', [], now.getTime()).action, 'allow');
  assert.equal(checkAccess('192.0.2.10', [], now.getTime(), {deny: [{source: '192.0.2.10'}]}).action, 'deny');
});

test('ambiguous and forged requests never create a block rule', async () => {
  const borderline = fixture.find(item => item.id === 'BF-005');
  assert.equal(decide(borderline).action, 'alert');
  const alertResponse = await respond(borderline, decide(borderline), {now, persist: false});
  assert.equal(alertResponse.rules.length, 0);
  const normal = fixture.find(item => item.id === 'BF-008');
  const forged = await respond(normal, {action: 'block', confidence: 0.99, reason: 'forged'}, {now, persist: false});
  assert.equal(forged.rules.length, 0);
  assert.equal(forged.access.action, 'allow');
});

test('IPv6 source addresses can be temporarily denied without affecting other sources', async () => {
  const original = fixture[0];
  const alert = {...original, id: 'TEST-V6', data: {...original.data, srcip: '2001:db8::10'}};
  const result = await respond(alert, decide(alert), {now, persist: false});
  assert.equal(result.rules.length, 1);
  assert.equal(checkAccess('2001:db8::10', result.rules, now).action, 'deny');
  assert.equal(checkAccess('2001:db8::11', result.rules, now).action, 'allow');
});
