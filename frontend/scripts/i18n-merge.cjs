/* eslint-disable */
/**
 * i18n wave merge + verify.
 *
 * Input: a JSON file holding the array returned by the i18n-rewrite-wave
 * workflow, each element: { file, namespace, keyPrefix, status,
 * translations: { en:{...}, es:{...}, zh:{...} }, ... }.
 *
 *   node scripts/i18n-merge.cjs <results.json>
 *
 * 1. Deep-merges each result's en/es/zh trees into
 *    public/locales/<lng>/<namespace>.json (created if absent), preserving
 *    existing keys.
 * 2. Key-coverage check: re-parses each rewritten .tsx, collects every
 *    t('literal'...) key, and verifies it resolves in en/<namespace>.json.
 *    Missing keys are reported (these would render as raw key strings, a
 *    bug tsc cannot catch).
 *
 * Exit code 1 if any missing keys, so a wave can be gated in CI / scripts.
 */
const fs = require('fs');
const path = require('path');
const ts = require('typescript');

const ROOT = path.resolve(__dirname, '..');
const LOCALES = path.join(ROOT, 'public', 'locales');
const LANGS = ['en', 'es', 'zh'];

const resultsPath = process.argv[2];
if (!resultsPath) { console.error('usage: node scripts/i18n-merge.cjs <results.json>'); process.exit(2); }
let results = JSON.parse(fs.readFileSync(resultsPath, 'utf8'));
// Accept a raw results array, or the workflow task-output wrapper
// ({ result: [...] }) so we can point straight at the .output file.
if (!Array.isArray(results)) results = results.result || results.results || results.files || [];

function deepMerge(target, src) {
  for (const k of Object.keys(src)) {
    if (src[k] && typeof src[k] === 'object' && !Array.isArray(src[k])) {
      target[k] = deepMerge(target[k] && typeof target[k] === 'object' ? target[k] : {}, src[k]);
    } else {
      target[k] = src[k];
    }
  }
  return target;
}

function loadNs(lng, ns) {
  const p = path.join(LOCALES, lng, `${ns}.json`);
  if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, 'utf8'));
  return {};
}
function saveNs(lng, ns, obj) {
  const dir = path.join(LOCALES, lng);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${ns}.json`), JSON.stringify(obj, null, 2) + '\n');
}

// ── 1. merge ───────────────────────────────────────────────────────────
const touchedNs = new Set();
let mergedKeys = 0;
const countLeaves = (o) => Object.values(o).reduce((n, v) => n + (v && typeof v === 'object' && !Array.isArray(v) ? countLeaves(v) : 1), 0);
for (const r of results) {
  if (!r || !r.namespace || !r.translations) continue;
  for (const lng of LANGS) {
    const tree = r.translations[lng];
    if (!tree || typeof tree !== 'object') continue;
    const merged = deepMerge(loadNs(lng, r.namespace), tree);
    saveNs(lng, r.namespace, merged);
    if (lng === 'en') mergedKeys += countLeaves(tree);
  }
  touchedNs.add(r.namespace);
}
console.log(`merged en keys: ~${mergedKeys} into namespaces: ${[...touchedNs].join(', ')}`);

// ── 2. key-coverage check ────────────────────────────────────────────────
function resolveKey(obj, dotted) {
  return dotted.split('.').reduce((o, part) => (o && typeof o === 'object' ? o[part] : undefined), obj);
}
// A key is "present" if it resolves directly OR via an i18next plural
// suffix (count-based t() calls like t('x.permissions', {count}) resolve
// to x.permissions_one / _other at runtime, the bare key won't exist).
const PLURAL_SUFFIXES = ['_one', '_other', '_zero', '_two', '_few', '_many'];
function keyPresent(en, key) {
  if (resolveKey(en, key) !== undefined) return true;
  return PLURAL_SUFFIXES.some((s) => resolveKey(en, key + s) !== undefined);
}
function collectTKeys(file) {
  const code = fs.readFileSync(file, 'utf8');
  const sf = ts.createSourceFile(file, code, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const keys = [];
  const visit = (n) => {
    if (ts.isCallExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === 't' && n.arguments.length) {
      const a = n.arguments[0];
      if (ts.isStringLiteral(a) || ts.isNoSubstitutionTemplateLiteral(a)) keys.push(a.text);
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return keys;
}

let missingTotal = 0;
for (const r of results) {
  if (!r || !r.file || !r.namespace) continue;
  const abs = path.join(ROOT, r.file.replace(/^.*?frontend[\\/]/, ''));
  const fileAbs = fs.existsSync(abs) ? abs : path.join(ROOT, r.file);
  if (!fs.existsSync(fileAbs)) { console.log(`  ! file not found to verify: ${r.file}`); continue; }
  const en = loadNs('en', r.namespace);
  const keys = collectTKeys(fileAbs);
  const missing = keys.filter((k) => !keyPresent(en, k));
  console.log(`  ${r.keyPrefix}: ${keys.length} t() keys, ${missing.length} missing`);
  for (const m of missing.slice(0, 20)) console.log(`      MISSING en[${r.namespace}]: ${m}`);
  missingTotal += missing.length;
}
console.log(missingTotal === 0 ? '\nKEY COVERAGE OK' : `\nKEY COVERAGE FAIL: ${missingTotal} missing`);
process.exit(missingTotal === 0 ? 0 : 1);
