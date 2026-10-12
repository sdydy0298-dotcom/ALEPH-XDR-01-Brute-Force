import {appendFile, readFile, writeFile, mkdir} from 'node:fs/promises';
import {dirname} from 'node:path';
import {isIP} from 'node:net';
import {fileURLToPath} from 'node:url';
import {decide} from './decide.mjs';
import {checkAccess} from '../../ztna/check.mjs';

const root = new URL('../', import.meta.url);
const denyFile = new URL('temporary-deny.json', root);
const logFile = new URL('alerts.log', root);
const idOf = value => /^[A-Za-z0-9_.:-]{1,96}$/.test(String(value ?? '')) ? String(value) : null;
const ipOf = value => typeof value === 'string' && isIP(value.trim()) ? value.trim() : null;
const sourceOf = alert => {
  const data = alert?.data ?? {};
  const direct = data.srcip ?? data.srcIp ?? data.src_ip ?? data.source_ip ??
    data.sourceIp ?? data.client_ip ?? alert?.srcip ?? alert?.src_ip ??
    alert?.source_ip ?? alert?.sourceIp ?? alert?.client_ip ??
    (typeof alert?.source === 'string' ? alert.source : alert?.source?.ip) ??
    data.win?.eventdata?.ipAddress ?? data['win.eventdata.ipAddress'];
  if (ipOf(direct)) return ipOf(direct);
  const raw = String(alert?.full_log ?? data.full_log ?? '');
  const match = raw.match(/\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b/i);
  return match ? ipOf(match[1]) : null;
};
const oneLine = value => String(value ?? '').replace(/[\r\n\t]/g, ' ').slice(0, 160);

async function readRules() {
  try {
    const rules = JSON.parse(await readFile(denyFile, 'utf8'));
    if (!Array.isArray(rules)) throw new Error('Invalid temporary deny list');
    return rules;
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}

// The scorer stays pure; only this responder is allowed to persist policy and alerts.
export async function respond(alert, decision, {now = new Date(), persist = true} = {}) {
  if (!decision || !['block', 'alert', 'record'].includes(decision.action) ||
      !Number.isFinite(decision.confidence) || decision.confidence < 0 || decision.confidence > 1) {
    throw new TypeError('Invalid decision');
  }
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) throw new TypeError('Invalid clock');

  const data = alert?.data && typeof alert.data === 'object' ? alert.data : {};
  const id = idOf(alert?.id ?? alert?.alert_id ?? alert?.alertId ?? (alert?.rule?.id ? 'rule-'+alert.rule.id+'-'+String(alert.timestamp??'').replace(/[^A-Za-z0-9]/g,'') : null));
  const source = sourceOf(alert);
  const rules = persist ? await readRules() : [];
  const active = rules.filter(rule => rule?.action === 'deny' && Number.isFinite(Date.parse(rule.expiresAt)) &&
    Date.parse(rule.expiresAt) > now.getTime());
  const successful = /^(success|successful|allowed|ok|passed)$/i.test(
    String(alert?.outcome ?? data.authentication?.status ?? ''));
  // Defense in depth: callers cannot forge a BLOCK verdict for an otherwise normal event.
  const verified = decide(alert);
  if (decision.action === 'block' && decision.confidence >= 0.85 &&
      verified.action === 'block' && source && id && !successful) {
    const rule = {
      id: 'xdr-' + id, action: 'deny', source, alertId: id,
      reason: oneLine(verified.reason), createdAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 15 * 60 * 1000).toISOString()
    };
    if (!active.some(existing => existing.id === rule.id)) active.push(rule);
  }

  const notification = {
    alertId: id ?? 'unknown', action: decision.action,
    confidence: decision.confidence, reason: oneLine(decision.reason)
  };
  if (persist) {
    await mkdir(dirname(fileURLToPath(denyFile)), {recursive: true});
    await writeFile(denyFile, JSON.stringify(active, null, 2) + '\n');
    // A notification is only a block or an alert; normal record events do not spam alerts.log.
    if (decision.action !== 'record') {
      await appendFile(logFile, JSON.stringify({...notification, at: now.toISOString()}) + '\n');
    }
  }
  return {
    notification: decision.action === 'record' ? null : notification,
    rules: active,
    access: source ? checkAccess(source, active, now.getTime()) :
      {action: 'allow', reason: '유효한 출발 주소 없음'}
  };
}
