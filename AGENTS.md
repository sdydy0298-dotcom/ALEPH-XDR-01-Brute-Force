# ALEPH XDR-01 implementation rules

- Judge contract: `xdr/brute-force/decide.mjs` exports `decide(alert)` only; no imports, file I/O, packages, or network calls.
- Confidence: >=0.85 block, >=0.50 alert, otherwise record.
- Do not log credentials, secrets, tokens, cookies, or unfiltered event bodies.
- Only unequivocal repeated failures generate a 15-minute deny candidate with an evidence alert ID.
- Keep `ztna/rules.json` unchanged; `ztna/evaluate.mjs` merges it with XDR temporary rules.
- The Wazuh-shaped fixture is copied without modification from ChoiTimo/aleph-defense-starter, which is the user's fork upstream; no live Wazuh server or operational ZTNA is connected.
- Test replay is deterministic and writes `xdr/alerts.log` and `xdr/temporary-deny.json`; re-run the test script before committing.
- Vercel public dashboard reflects the stored simulation report and cannot change access policy.
