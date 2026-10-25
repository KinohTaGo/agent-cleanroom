#!/usr/bin/env node
// check-distrusted-roots.js — build-time guard for agent-cleanroom images.
//
// Fails (exit 1) if a trust store in the image still trusts a root whose
// subordinate CA keys were compromised in October 2026 (eMudhra "G3" family,
// reachable either directly or through Sectigo's cross-sign to AAA).
//
// Usage: node check-distrusted-roots.js <pem-bundle>...
//   Each argument is a PEM bundle (e.g. /etc/ssl/certs/ca-certificates.crt).
//   Node's own built-in store (tls.rootCertificates) is always checked too.
//
// Matching is by SHA-256 of the DER SubjectPublicKeyInfo, not by name, so a
// re-issued certificate for the same key is still caught.
// Exit codes: 0 = none found, 1 = found, 2 = could not read a bundle / parsed 0 certs.
'use strict';
const { X509Certificate, createHash } = require('crypto');
const tls = require('tls');
const fs = require('fs');

const DISTRUSTED = {
  BD153ED7B0434F6886B17BCE8BBE84ED340C7132D702A8F4FA318F756ECBD6F3: 'AAA Certificate Services (Sectigo cross-sign path)',
  C619E4780ED8E0ABEDA24AD732567DE4383A7EA941338F6D1A7D1B49AC792FE9: 'emSign Root TLS CA - G3',
  '8D417DB2DD8BF5E3084D1E3F196D583849D81BDD4C00C70B9D39369E96B8C782': 'emSign ECC Root CA - G3',
};

function spkiSha256(pem) {
  const der = new X509Certificate(pem).publicKey.export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(der).digest('hex').toUpperCase();
}

function scan(label, pems) {
  if (pems.length === 0) {
    console.error(`[roots] ${label}: parsed 0 certificates — cannot vouch for it`);
    return 2;
  }
  const found = [...new Set(pems.map(spkiSha256))].filter((h) => h in DISTRUSTED);
  for (const h of found) console.error(`[roots] ${label}: still trusts ${DISTRUSTED[h]} (SPKI ${h.slice(0, 16)}…)`);
  console.error(`[roots] ${label}: ${pems.length} certs, ${found.length} distrusted`);
  return found.length ? 1 : 0;
}

let rc = scan(`node ${process.version} built-in`, tls.rootCertificates);
for (const path of process.argv.slice(2)) {
  let text;
  try { text = fs.readFileSync(path, 'utf8'); } catch (e) {
    console.error(`[roots] ${path}: ${e.code || e.message}`);
    rc = Math.max(rc, 2);
    continue;
  }
  const pems = text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
  rc = Math.max(rc, scan(path, pems));
}
process.exit(rc);
