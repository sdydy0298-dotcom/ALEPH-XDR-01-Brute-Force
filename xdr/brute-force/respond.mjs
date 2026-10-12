import {appendFile,readFile,writeFile,mkdir} from 'node:fs/promises';
import {dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {checkAccess} from '../../ztna/check.mjs';
const root=new URL('../',import.meta.url);
const denyFile=new URL('temporary-deny.json',root);
const logFile=new URL('alerts.log',root);
const safeId = value => /^[A-Za-z0-9_.-]{1,64}$/.test(String(value||''))?String(value):'unknown';
const safeSource = value => typeof value==='string' && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) && value.split('.').every(p=>Number(p)<=255) ? value : null;
export async function respond(alert,decision,{now=new Date(),persist=true}={}) {
  const data=alert?.data||{};
  const source=safeSource(data.srcip??alert?.srcip??alert?.source_ip);
  const id=safeId(alert?.id);
  const message={alertId:id,action:decision.action,confidence:decision.confidence,reason:decision.reason};
  const rules = persist ? await readFile(denyFile,'utf8').then(JSON.parse).catch(err=>{if(err.code==='ENOENT')return [];throw err;}) : [];
  const active=rules.filter(r=>new Date(r.expiresAt)>now);
  const explicitlyNormal=alert?.outcome==='success'||data?.authentication?.status==='success';
  if(decision.action==='block' && decision.confidence>=0.85 && source && !explicitlyNormal && id!=='unknown') {
    const rule={id:'xdr-'+id,action:'deny',source,alertId:id,reason:decision.reason,createdAt:now.toISOString(),expiresAt:new Date(now.getTime()+15*60*1000).toISOString()};
    if(!active.some(r=>r.id===rule.id)) active.push(rule);
  }
  if(persist) {
    await mkdir(dirname(fileURLToPath(denyFile)),{recursive:true});
    await writeFile(denyFile,JSON.stringify(active,null,2)+'\n');
    await appendFile(logFile,JSON.stringify({...message,at:now.toISOString()})+'\n');
  }
  return {notification:message,rules:active,access:source?checkAccess(source,active,now.getTime()):{action:'allow',reason:'유효한 출발 주소 없음'}};
}
