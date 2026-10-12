// Existing ZTNA policy is evaluated first; XDR denial rules are an additional gate.
export function checkAccess(source, xdrRules = [], at = Date.now(), basePolicy = {}) {
  const time = at instanceof Date ? at.getTime() : Number(at);
  if (!Number.isFinite(time)) throw new TypeError('Invalid evaluation time');
  const matches = rule => rule && (rule.source === source || rule.ip === source);
  const staticDeny = Array.isArray(basePolicy.deny) &&
    basePolicy.deny.some(rule => matches(rule) && (!rule.expiresAt || Date.parse(rule.expiresAt) > time));
  if (staticDeny) return {action: 'deny', reason: '기존 ZTNA 거부 규칙'};
  const xdrDeny = Array.isArray(xdrRules) && xdrRules.some(rule =>
    rule.action === 'deny' && matches(rule) && Date.parse(rule.expiresAt) > time);
  if (xdrDeny) return {action: 'deny', reason: '유효한 XDR 임시 거부 규칙'};
  return {action: 'allow', reason: '활성 거부 규칙 없음'};
}
