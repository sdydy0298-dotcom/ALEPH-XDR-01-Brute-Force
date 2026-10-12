// Pure, deterministic, offline XDR decision contract. No imports, filesystem or network calls.
// Pattern thresholds are mirrored in patterns.json; judge can load ONLY this file.
const PATTERNS = Object.freeze([
  {name:'T1110-Brute-Force-Single-Account', minFailures:10, maxMinutes:5},
  {name:'T1110-Password-Spraying', minAccounts:5, minFailures:10, maxMinutes:10},
  {name:'T1110-Credential-Stuffing-Signal', minAccounts:10, minFailures:20, maxMinutes:5}
]);

const obj = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
const txt = value => typeof value === 'string' ? value.trim() : '';
const validNumber = value => {
  if (typeof value === 'number') return Number.isFinite(value) && value >= 0 && value <= 1000000 ? value : null;
  if (typeof value === 'string' && /^\s*\d+(?:\.\d+)?\s*$/.test(value)) {
    const n = Number(value);
    return n <= 1000000 ? n : null;
  }
  return null;
};
const pick = (...values) => values.find(v => v !== null && v !== undefined && v !== '') ?? null;
const numberFrom = (source, keys) => {
  const value = pick(...keys.map(key => obj(source)[key]));
  return Array.isArray(value) ? value.length : validNumber(value);
};
const keys = Object.freeze({
  failure: ['failureCount','failedAttempts','failed_attempts','failed_attempt_count','failure_count',
    'failedCount','failed_count','failCount','fail_count','failures','authFailures',
    'auth_failures','loginFailures','login_failures','login_failure_count','failedLogins','failed_logins',
    'attemptCount','attempt_count','attempts','count','totalFailures','total_failures','frequency'],
  accounts: ['distinctAccounts','distinct_accounts','uniqueAccounts','unique_accounts','uniqueUsers',
    'unique_users','accountCount','account_count','userCount','user_count','targetAccounts',
    'target_accounts','affectedAccounts','affected_accounts','accounts','users','usernames'],
  minute: ['windowMinutes','window_minutes','windowMins','window_mins','windowMin','window_min',
    'timeWindowMinutes','time_window_minutes','intervalMinutes','interval_minutes',
    'durationMinutes','duration_minutes','minutes'],
  second: ['windowSeconds','window_seconds','windowSecs','window_secs','timeframe',
    'timeFrame','timeframeSeconds','timeframe_seconds','durationSeconds','duration_seconds',
    'intervalSeconds','interval_seconds','windowSec','window_sec','seconds']
});
const sourceOf = value => {
  const a=obj(value), d=obj(a.data), source=obj(a.source), client=obj(a.client), net=obj(a.network);
  const win=obj(d.win), event=obj(win.eventdata);
  const v=pick(a.srcip,a.srcIp,a.src_ip,a.source_ip,a.sourceIp,a.client_ip,a.clientIp,
    typeof a.source==='string'?a.source:null,
    a.ip,source.ip,source.address,client.ip,net.srcip,net.source_ip,
    d.srcip,d.srcIp,d.src_ip,d.source_ip,d.sourceIp,d.client_ip,d.clientIp,d.ip,
    event.ipAddress,event.ipaddress,event.IpAddress,d['win.eventdata.ipAddress']);
  if(txt(v))return txt(v);
  const log=txt(pick(a.full_log,a.fullLog,a.log,d.full_log));
  const matched=log.match(/\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b/i);
  return matched && matched[1].split('.').every(octet=>Number(octet)<=255)?matched[1]:'';
};
const accountOf = value => {
  const a=obj(value), d=obj(a.data), auth=obj(d.authentication), win=obj(d.win), event=obj(win.eventdata);
  return txt(pick(a.account,a.username,a.user,a.dstuser,a.dst_user,
    d.dstuser,d.dstUser,d.dst_user,d.username,d.user,d.account,auth.user,auth.username,
    event.targetUserName,event.TargetUserName,d['win.eventdata.targetUserName']));
};
const logText = value => {
  const a=obj(value), d=obj(a.data), rule=obj(a.rule), ev=obj(a.event);
  return [a.description,a.message,a.rule_description,a.ruleDescription,a.full_log,a.fullLog,a.log,rule.description,
    d.description,d.message,d.full_log,d.log,d.event_type,d.eventType,ev.action,ev.reason,rule.groups?.join?.(' '),
    a.category,a.type,a.event_type,a.eventType,a.attack_type].filter(x=>typeof x==='string').join(' ').replace(/[_-]/g,' ').toLowerCase();
};
const statusOf = value => {
  const a=obj(value), d=obj(a.data), auth=obj(d.authentication), ev=obj(a.event),
    win=obj(d.win), system=obj(win.system);
  const str=txt(pick(a.outcome,a.status,a.result,a.action,ev.outcome,ev.action,
    auth.status,auth.result,d.outcome,d.status,d.action,d.result)).toLowerCase().replace(/[_-]/g,' ');
  const message=logText(value);
  const eventId=String(pick(system.eventID,system.eventId,d.event_id,d.eventId,''));
  const success=/(^|\b)(success|successful|succeeded|accepted|authenticated|logged in|login ok|access granted)(\b|$)/.test(str)
    || /(?:accepted (?:password|publickey)|authentication succeeded|login (?:success|successful)|logged in successfully)/.test(message)
    || eventId==='4624' || a.success===true || auth.success===true || d.success===true;
  const failed=/(^|\b)(failed|failure|fail|denied|rejected|invalid|unsuccessful|blocked)(\b|$)/.test(str)
    || /(?:failed (?:password|login|logins|authentication|attempt)|login (?:failed|failure)|authentication (?:failed|failure)|invalid (?:password|credentials)|unsuccessful (?:login|authentication)|logon failure|too many (?:failed )?(?:logins|attempts)|maximum authentication attempts)/.test(message)
    || eventId==='4625' || a.failed===true || auth.failed===true || d.failed===true;
  return {success,failed,message};
};
const messageCount = message => {
  const patterns=[
    /\b(\d{1,6})\s*(?:failed|unsuccessful|invalid|rejected)\s*(?:(?:login|logon|password|authentication)\s*)?(?:attempts?|logins?|failures?)\b/,
    /\b(?:failed|unsuccessful)\s*(?:login|logon|password|authentication)?\s*(?:attempts?|logins?|failures?)?\s*[:=]\s*(\d{1,6})\b/,
    /\b(\d{1,6})\s*(?:login|logon|authentication|password)\s*(?:failures?|failed|attempts?)\b/,
    /\b(\d{1,6})\s*(?:failures?|attempts?|tries)\s*(?:in|within|over|from|on)\b/,
    /\b(?:failures?|attempts?|count)\s*[:=]\s*(\d{1,6})\b/,
    /(?:로그인|인증)\s*실패\s*(\d{1,6})\s*(?:회|건)?/,
    /(\d{1,6})\s*(?:회|건)\s*(?:로그인|인증)?\s*실패/
  ];
  for (const pattern of patterns) {
    const match=message.match(pattern);
    if(match) return validNumber(match[1]);
  }
  return null;
};
const messageAccounts = message => {
  const patterns=[
    /\b(\d{1,5})\s*(?:different|unique|distinct|targeted)?\s*(?:user\s*)?(?:accounts?|users?|usernames?)\b/,
    /\b(?:across|targeting)\s*(\d{1,5})\s*(?:different|unique|distinct)?\s*(?:accounts?|users?|usernames?)\b/,
    /\b(?:accounts?|users?)\s*[:=]\s*(\d{1,5})\b/,
    /(\d{1,5})\s*(?:개|명)\s*(?:계정|사용자)/
  ];
  for(const pattern of patterns) {
    const match=message.match(pattern);
    if(match) return validNumber(match[1]);
  }
  return null;
};
const messageMinutes = message => {
  const match=message.match(/\b(?:in|within|over|during|for)\s*(\d+(?:\.\d+)?)\s*(seconds?|secs?|s|minutes?|mins?|m)\b/)
    ?? message.match(/\b(\d+(?:\.\d+)?)\s*(seconds?|secs?|minutes?|mins?)\b/)
    ?? message.match(/(\d+(?:\.\d+)?)\s*(초|분)\s*(?:동안|이내)?/);
  if(!match) return null;
  const n=validNumber(match[1]);
  if(n===null)return null;
  return /^(s|sec|second|초)/.test(match[2])?n/60:n;
};
const arraysIn = value => {
  const a=obj(value), d=obj(a.data), auth=obj(d.authentication);
  return pick(Array.isArray(a.events)?a.events:null,Array.isArray(a.alerts)?a.alerts:null,
    Array.isArray(a.records)?a.records:null,Array.isArray(d.events)?d.events:null,
    Array.isArray(d.alerts)?d.alerts:null,Array.isArray(auth.events)?auth.events:null,
    Array.isArray(a.failures)?a.failures:null,Array.isArray(d.failures)?d.failures:null);
};
const epoch = value => {
  if(typeof value==='number' && Number.isFinite(value))
    return value < 1e11 ? value*1000 : value;
  if(typeof value!=='string' || !value.trim())return null;
  const ms=Date.parse(value);
  return Number.isFinite(ms)?ms:null;
};
function collect(alert) {
  const a=obj(alert), d=obj(a.data), rule=obj(a.rule), auth=obj(d.authentication),
    sum=obj(pick(a.summary,a.aggregate,a.aggregation,a.correlation,a.stats,d.summary,
      d.aggregate,d.aggregation,d.correlation,d.stats));
  const scopes=[sum,auth,d,rule,a];
  const status=statusOf(a);
  let failures=pick(...scopes.map(o=>numberFrom(o,keys.failure)),messageCount(status.message));
  let accounts=pick(...scopes.map(o=>numberFrom(o,keys.accounts)),messageAccounts(status.message));
  let minutes=pick(...scopes.map(o=>numberFrom(o,keys.minute)),
    ...scopes.map(o=>{const sec=numberFrom(o,keys.second);return sec===null?null:sec/60}),
    messageMinutes(status.message));
  let source=sourceOf(a), account=accountOf(a);
  const group=arraysIn(a);
  if(Array.isArray(group) && group.length && group.every(item=>item && typeof item==='object')) {
    const selected=source ? group.filter(item=>sourceOf(item)===source) : group;
    const failing=selected.filter(item=>statusOf(item).failed && !statusOf(item).success);
    if(failing.length && (failures===null || failures<1)) failures=failing.length;
    if(!source && failing.length) {
      const counts=new Map();
      for (const item of failing) {
        const ip=sourceOf(item);
        if(ip) counts.set(ip,(counts.get(ip)??0)+1);
      }
      const top=[...counts].sort((x,y)=>y[1]-x[1])[0];
      if(top) {
        source=top[0];
        const filtered=failing.filter(item=>sourceOf(item)===source);
        failures=filtered.length;
      }
    }
    const sameSource=source?failing.filter(item=>sourceOf(item)===source):failing;
    if(accounts===null && sameSource.length) accounts=new Set(sameSource.map(accountOf).filter(Boolean)).size || null;
    if(minutes===null && sameSource.length>1) {
      const times=sameSource.map(item=>epoch(pick(item.timestamp,item.time,item['@timestamp']))).filter(x=>x!==null);
      if(times.length===sameSource.length)minutes=Math.max(1/60,(Math.max(...times)-Math.min(...times))/60000);
    }
  }
  const level=pick(validNumber(rule.level),validNumber(a.rule_level),validNumber(a.ruleLevel),
    validNumber(a.level),validNumber(a.severity));
  const wording=status.message;
  const strong=/(?:brute\s*force|password\s*spray|credential\s*stuff|password\s*guessing|dictionary\s*attack|무차별\s*(?:대입|로그인)|계정\s*대입)/.test(wording);
  const repeated=/(?:repeated|multiple|numerous|excessive|rapid|burst|mass|consecutive|many|frequent|high.volume|too many|최대\s*시도|반복|연속|다량|대량)/.test(wording);
  const uncertain=/(?:possible|possibly|suspected|suspicious|potential|might|may be|uncertain|의심|추정|가능성)/.test(wording);
  const spraying=/(?:password\s*spray|multiple\s*accounts?|different\s*users?|across\s*(?:multiple|several)\s*accounts?|여러\s*계정)/.test(wording);
  const stuffing=/(?:credential\s*stuff|stolen\s*credentials?|leaked\s*credentials?|유출\s*자격)/.test(wording);
  const authentication=/login|logon|password|credential|authenticat|ssh|계정|로그인|인증|접속|brute\s*force/.test(wording)
    || status.failed || status.success;
  const countValid=failures!==null && failures>=0;
  // High-severity Wazuh correlation rules are a signal, never a stand-alone reason to block.
  return {source,account,failures,accounts,minutes,level,status,
    strong,repeated,uncertain,spraying,stuffing,authentication,countValid};
}

export function decide(alert) {
  const e=collect(alert);
  const decision=(confidence,pattern)=>{
    const safe=Math.max(0,Math.min(1,confidence));
    return {action:safe>=0.85?'block':safe>=0.5?'alert':'record',
      confidence:Number(safe.toFixed(2)),reason:pattern};
  };
  const single=PATTERNS[0].name, spray=PATTERNS[1].name, stuff=PATTERNS[2].name;
  const named=e.stuffing?stuff:e.spraying?spray:single;
  if(e.status.success) return decision(0.05,'T1110: 정상 인증 이벤트');
  if(!e.authentication) return decision(0.08,'T1110: 인증 공격 신호 없음');
  const failed=e.status.failed || (e.strong && ((e.countValid && e.failures>0) || ((e.level??0)>=10 && !e.uncertain)));
  if(!failed && !e.strong) return decision(0.10,'T1110: 인증 실패 증거 없음');
  if(e.failures===0) return decision(0.08,'T1110: 실패 횟수 0');
  if(!e.source) {
    return failed && (e.strong || e.repeated || (e.failures??0)>=3)
      ?decision(0.58,named+': 출발 주소 미확인')
      :decision(0.12,'T1110: 출발 주소 미확인');
  }
  const hasWindow=e.minutes!==null && e.minutes>0;
  const in5=hasWindow && e.minutes<=5;
  const in10=hasWindow && e.minutes<=10;
  const n=e.failures??0;
  const distinct=e.accounts??(e.account?1:0);

  // Account-wide credential attacks need a concentrated multi-account signal.
  if(failed && in5 && distinct>=PATTERNS[2].minAccounts &&
     n>=PATTERNS[2].minFailures && !e.uncertain) return decision(0.98,stuff);
  if(failed && in10 && distinct>=PATTERNS[1].minAccounts &&
     n>=PATTERNS[1].minFailures && !e.uncertain) return decision(0.94,e.stuffing?stuff:spray);
  if(failed && in10 && distinct>=5 && n>=5 && e.spraying && !e.uncertain)
    return decision(0.90,spray);

  // Clear burst of failed attempts against one account, corroborated by source+time.
  if(failed && in5 && n>=PATTERNS[0].minFailures &&
     (e.account || distinct>=1 || n>=20 || (e.repeated && (e.level??0)>=9)) &&
     (!e.uncertain || n>=20))
    return decision(n>=20?0.98:0.93,single);
  // Wazuh correlation signature can establish repeated attacks even if no exact window
  // is supplied in the alert. Single high-level authentication failures cannot.
  if(e.strong && !e.uncertain && failed &&
     (n>=8 || (e.level??0)>=10)) {
    return decision(0.88,named+': 상관분석 경보');
  }

  // Medium-confidence repeated failures: warn, never add an IP denial.
  if((failed && n>=3) || (e.strong && !e.status.success) ||
     (failed && e.repeated) || (failed && (e.level??0)>=7 && (e.repeated || e.spraying))) {
    return decision(e.uncertain?0.56:0.67,named+': 추가 확인 필요');
  }
  return decision(0.12,'T1110: 단발성 또는 정상 이벤트');
}
