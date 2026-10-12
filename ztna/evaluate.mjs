import {readFile} from 'node:fs/promises';
import {checkAccess} from './check.mjs';

// This is the real file-backed access path used by the local ZTNA simulation.
// rules.json is READ ONLY; the XDR responder updates a separate temporary rule file.
export async function evaluateAccess(source, at = Date.now()) {
  const [original, dynamic] = await Promise.all([
    readFile(new URL('./rules.json', import.meta.url), 'utf8'),
    readFile(new URL('../xdr/temporary-deny.json', import.meta.url), 'utf8')
  ]);
  const base = JSON.parse(original);
  const temporary = JSON.parse(dynamic);
  if (!Array.isArray(temporary)) throw new Error('Invalid dynamic rule file');
  return checkAccess(source, temporary, at, base);
}
