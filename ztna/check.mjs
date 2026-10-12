export function checkAccess(source, rules=[], at=Date.now()) {
  const blocked = rules.some(r=>r.action==='deny' && r.source===source && new Date(r.expiresAt).getTime()>at);
  return {action:blocked?'deny':'allow',reason:blocked?'유효한 XDR 임시 거부 규칙':'거부 규칙 없음'};
}
