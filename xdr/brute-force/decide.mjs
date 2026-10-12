// Offline judge contract: this file intentionally has no imports or side effects.
// Canonical patterns mirrored from patterns.json.
const PATTERNS = Object.freeze([
  {name:'T1110-Brute-Force-Single-Account', failures:10, minutes:5, distinctAccounts:1},
  {name:'T1110-Password-Spraying', failures:5, minutes:10, distinctAccounts:5},
  {name:'T1110-Credential-Stuffing-Signal', failures:20, minutes:5, distinctAccounts:10}
]);
const numeric = value => (typeof value === 'number' && Number.isFinite(value) ? value : (typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : null));
const text = value => typeof value === 'string' ? value.trim() : '';
const first = (...values) => values.find(v => v !== null && v !== undefined && v !== '') ?? null;
const countOf = value => Array.isArray(value) ? value.length : numeric(value);
function evidence(alert) {
  const a = alert && typeof alert === 'object' ? alert : {};
  const data = a.data && typeof a.data === 'object' ? a.data : {};
  const auth = data.authentication && typeof data.authentication === 'object' ? data.authentication : {};
  const sum = first(a.summary, a.aggregate, data.summary, data.aggregate) || {};
  const source = first(a.srcip, a.source_ip, data.srcip, data.src_ip, data.srcIp, sum.source_ip);
  const account = first(a.account, a.username, data.dstuser, data.srcuser, data.user, sum.account);
  const failures = first(countOf(sum.failedAttempts), countOf(sum.failureCount), countOf(sum.failures), countOf(a.failureCount), countOf(data.failure_count), countOf(data.failed_attempts));
  const accounts = first(countOf(sum.distinctAccounts), countOf(sum.uniqueAccounts), countOf(sum.accountCount), countOf(data.distinct_accounts), Array.isArray(sum.accounts) ? new Set(sum.accounts.filter(x=>typeof x==='string')).size : null);
  const minutes = first(numeric(sum.windowMinutes), numeric(sum.window_minutes), numeric(data.window_minutes), numeric(a.windowMinutes));
  const outcome = text(first(a.outcome,a.event?.outcome,auth.status,data.status,data.action)).toLowerCase();
  const message = text(first(a.description,a.rule?.description,data.message));
  const ruleId = numeric(first(a.rule?.id,a.rule_id));
  const explicitlySuccess = /^(success|successful|allowed|ok|passed)$/.test(outcome) || /\b(login successful|authentication succeeded|login success)\b/i.test(message);
  const explicitFailure = /^(failed|failure|denied|invalid|rejected)$/.test(outcome) || /\b(login failed|authentication failure|failed login|invalid password|authentication failed)\b/i.test(message);
  return {source: typeof source==='string' && source.length>0, account:typeof account==='string' && account.length>0, failures,accounts,minutes,explicitlySuccess,explicitFailure,ruleId};
}
export function decide(alert) {
  const e = evidence(alert);
  const record = reason => ({action:'record',confidence:0.05,reason});
  const output = (confidence,name) => ({action:confidence>=0.85?'block':confidence>=0.5?'alert':'record',confidence:Number(confidence.toFixed(2)),reason:name});
  if(e.explicitlySuccess) return record('정상 인증 성공');
  if(!e.source) return record('출발 주소 증거 없음');
  if(e.failures===null || e.failures<1 || e.minutes===null || e.minutes<=0) {
    return e.explicitFailure && e.account && e.ruleId!==null ? output(0.55,'T1110-Brute-Force-Single-Account: 단일 실패 경보') : record('집계된 실패 증거 부족');
  }
  if(!e.explicitFailure) return record('인증 실패 여부 불명확');
  if(e.minutes>10) return output(0.3,'T1110: 시간 창 초과');
  if(e.accounts!==null && e.accounts>=10 && e.failures>=20 && e.minutes<=5) return output(0.96,PATTERNS[2].name);
  if(e.accounts!==null && e.accounts>=5 && e.failures>=5 && e.minutes<=10) return output(0.91,PATTERNS[1].name);
  if(e.account && (e.accounts===null || e.accounts===1) && e.failures>=10 && e.minutes<=5) return output(0.94,PATTERNS[0].name);
  if(e.failures>=3 && e.minutes<=10) return output(0.62,'T1110-Brute-Force-Single-Account: 반복 실패 의심');
  return output(0.12,'T1110: 공격 증거 부족');
}
