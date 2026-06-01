/* eslint-disable */
/**
 * i18n cross-language verifier (en vs es vs zh).
 *
 *   node scripts/i18n-verify.cjs
 *
 * For every namespace JSON, checks:
 *   1. KEY PARITY, keys present in en but missing in es/zh (→ English
 *                        fallback at runtime; an incomplete translation).
 *                        Also keys in es/zh that don't exist in en (orphans).
 *   2. INTERPOLATION, the set of {{placeholders}} for each leaf must match
 *                        across en/es/zh (mismatch → broken variable render).
 *   3. UNTRANSLATED zh, zh leaf identical to en AND containing lowercase
 *                        Latin prose AND not a known technical/brand term
 *                        (→ likely an English string left in the zh file).
 *
 * Exit 1 if any parity gap or interpolation mismatch is found.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const LOC = path.join(ROOT, 'public', 'locales');
const LANGS = ['en', 'es', 'zh'];

// Terms that are legitimately identical across languages (brands, protocols,
// acronyms, units). A zh leaf equal to en is only flagged if it's NOT one of
// these and contains lowercase Latin prose.
const TECH = new Set(
  ['VLAN','VLANs','SSID','SSIDs','PoE','VPN','DNS','DHCP','API','NVR','NVRs','DVR','PTZ','FPS','SAML','OIDC','LDAP','S3','SFTP','FTP','FTPS','NFS','NAT','QoS','MTU','SNMP','IP','IPv4','IPv6','MAC','CPU','RAM','GPU','URL','SSH','TLS','SSL','PBX','IVR','DID','DIDs','SIP','RTSP','ONVIF','mDNS','SSDP','ARP','ICMP','WebDAV','OAuth2','SSO','MFA','CIDR','UTC','GMT','CET','JST','CST','Webhook','Webhooks','Codec','LACP','STP','MOH','CID','IDS','IPS','OSD','OSDs','PG','PGs','SLA','HA','SDN','PBS','Ceph','REC','OK','LAN','WAN','WLAN','WiFi','LED','VM','VMs','VMID','CT','CTs','OpenAPI','FreeSDN','Tailscale','WireGuard','OpenVPN','Netbird','ZeroTier','IPsec','FreePBX','Asterisk','FreeSWITCH','3CX','OPNsense','pfSense','MikroTik','OpenWrt','OpenWRT','Omada','UniFi','Ubiquiti','Hikvision','Axis','Meraki','Proxmox','Dropbox','Nextcloud','ownCloud','Slack','Fernet','Ollama','OpenAI','Anthropic','GPT-4o','Beta','Premium','TP-Link','Cisco','Email','Hotspot'].map((s) => s.toLowerCase())
);

function flatten(obj, prefix = '', out = {}) {
  for (const k of Object.keys(obj)) {
    const v = obj[k];
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, out);
    else out[key] = v;
  }
  return out;
}
const load = (lng, ns) => {
  const p = path.join(LOC, lng, `${ns}.json`);
  return fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, 'utf8')) : null;
};
const placeholders = (s) => {
  if (typeof s !== 'string') return [];
  return (s.match(/\{\{\s*[\w]+\s*\}\}/g) || []).map((x) => x.replace(/[{}\s]/g, '')).sort();
};
const looksEnglishProse = (s) =>
  typeof s === 'string' && /[a-z]{2,}/.test(s) && /\s/.test(s) && s.length > 6;

const namespaces = fs.readdirSync(path.join(LOC, 'en')).filter((f) => f.endsWith('.json')).map((f) => f.replace('.json', ''));

let totalEnKeys = 0, missingEs = 0, missingZh = 0, orphan = 0, interpBad = 0, zhUntrans = 0;
const report = [];

for (const ns of namespaces) {
  const en = flatten(load('en', ns) || {});
  const es = flatten(load('es', ns) || {});
  const zh = flatten(load('zh', ns) || {});
  const enKeys = Object.keys(en);
  totalEnKeys += enKeys.length;

  const mEs = enKeys.filter((k) => !(k in es));
  const mZh = enKeys.filter((k) => !(k in zh));
  const orphEs = Object.keys(es).filter((k) => !(k in en));
  const orphZh = Object.keys(zh).filter((k) => !(k in en));
  missingEs += mEs.length; missingZh += mZh.length; orphan += orphEs.length + orphZh.length;

  const interp = [];
  for (const k of enKeys) {
    if (!(k in es) && !(k in zh)) continue;
    const pe = placeholders(en[k]).join(',');
    if (k in es && placeholders(es[k]).join(',') !== pe) interp.push(`${k} [es: en={${pe}} es={${placeholders(es[k]).join(',')}}]`);
    if (k in zh && placeholders(zh[k]).join(',') !== pe) interp.push(`${k} [zh: en={${pe}} zh={${placeholders(zh[k]).join(',')}}]`);
  }
  interpBad += interp.length;

  const zhEng = [];
  for (const k of enKeys) {
    if (!(k in zh)) continue;
    if (zh[k] === en[k] && looksEnglishProse(en[k]) && !TECH.has(String(en[k]).toLowerCase())) zhEng.push(`${k} = ${JSON.stringify(en[k]).slice(0, 50)}`);
  }
  zhUntrans += zhEng.length;

  if (mEs.length || mZh.length || orphEs.length || orphZh.length || interp.length || zhEng.length) {
    report.push({ ns, enKeys: enKeys.length, mEs, mZh, orphEs, orphZh, interp, zhEng });
  }
}

console.log(`\n=== i18n cross-language verification (${namespaces.length} namespaces, ${totalEnKeys} en keys) ===`);
console.log(`missing in es: ${missingEs} | missing in zh: ${missingZh} | orphans: ${orphan} | interpolation mismatches: ${interpBad} | suspected-English zh leaves: ${zhUntrans}\n`);

for (const r of report) {
  console.log(`── ${r.ns} (${r.enKeys} keys) ──`);
  if (r.mEs.length) console.log(`  missing es (${r.mEs.length}): ${r.mEs.slice(0, 8).join(', ')}${r.mEs.length > 8 ? ' …' : ''}`);
  if (r.mZh.length) console.log(`  missing zh (${r.mZh.length}): ${r.mZh.slice(0, 8).join(', ')}${r.mZh.length > 8 ? ' …' : ''}`);
  if (r.orphEs.length) console.log(`  orphan es (${r.orphEs.length}): ${r.orphEs.slice(0, 6).join(', ')}${r.orphEs.length > 6 ? ' …' : ''}`);
  if (r.orphZh.length) console.log(`  orphan zh (${r.orphZh.length}): ${r.orphZh.slice(0, 6).join(', ')}${r.orphZh.length > 6 ? ' …' : ''}`);
  if (r.interp.length) console.log(`  INTERPOLATION (${r.interp.length}): ${r.interp.slice(0, 6).join(' | ')}`);
  if (r.zhEng.length) console.log(`  zh==en prose (${r.zhEng.length}): ${r.zhEng.slice(0, 6).join(' | ')}`);
}

const hardFail = missingEs + missingZh + interpBad;
console.log(hardFail === 0 ? '\nPARITY + INTERPOLATION OK' : `\nFAIL: ${hardFail} parity/interpolation issues`);
process.exit(hardFail === 0 ? 0 : 1);
