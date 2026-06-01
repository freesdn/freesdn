/* eslint-disable */
/**
 * i18n extraction inventory (non-destructive).
 *
 * Walks every .tsx under src/ with the TypeScript compiler API and reports
 * user-facing hardcoded string literals that should be wired through t():
 *   1. JSX text nodes:           <p>Hello world</p>
 *   2. User-facing JSX attrs:    <X title="Total Backups" placeholder="Search..." />
 *   3. User-facing object props: { title: 'Total Backups', message: 'Queued' }
 *      (covers PageHeader/StatsGrid/EmptyState/addNotification patterns)
 *
 * Skips: strings already inside t(...) / i18nKey, non-user-facing attrs
 * (className, href, id, key, type, variant, value, name, icon, …), and
 * non-translatable literals (single tokens, numbers, urls, css, symbols).
 *
 * Output: JSON report at the path given as argv[2] (default
 * <os-tmpdir>/freesdn-i18n-report.json) + a ranked summary to stdout.
 */
const fs = require('fs');
const path = require('path');
const ts = require('typescript');

const os = require('os');
const ROOT = path.resolve(__dirname, '..');
const SRC = path.join(ROOT, 'src');
// First non-flag CLI arg is the report path; default to a portable temp file.
const OUT = process.argv.slice(2).find((a) => !a.startsWith('--')) ||
  path.join(os.tmpdir(), 'freesdn-i18n-report.json');

// Attribute names that render user-visible text.
const UI_ATTRS = new Set([
  'title', 'description', 'label', 'placeholder', 'heading', 'subheading',
  'subtitle', 'message', 'tooltip', 'alt', 'caption', 'helpertext', 'hint',
  'submitlabel', 'cancellabel', 'confirmlabel', 'confirmtext', 'canceltext',
  'emptytitle', 'emptydescription', 'emptymessage', 'emptytext', 'errortitle',
  'errormessage', 'header', 'text', 'content', 'aria-label', 'badge',
]);
// Object-literal property keys that render user-visible text (StatsGrid,
// EmptyState action, PageHeader, addNotification, column headers, …).
const UI_OBJ_KEYS = new Set([
  'title', 'description', 'label', 'message', 'placeholder', 'heading',
  'subtitle', 'tooltip', 'header', 'text', 'caption', 'hint', 'emptymessage',
  'name', // column/field display name in DataTable column defs
]);
// Attributes that are NEVER user-facing, hard skip even if string-valued.
const SKIP_ATTRS = new Set([
  'classname', 'class', 'href', 'to', 'id', 'key', 'type', 'variant', 'size',
  'value', 'name', 'icon', 'role', 'htmlfor', 'rel', 'target', 'src', 'style',
  'datatestid', 'data-testid', 'autocomplete', 'inputmode', 'pattern', 'lang',
  'dir', 'as', 'color', 'fill', 'stroke', 'viewbox', 'd', 'path', 'mode',
  'method', 'action', 'accept', 'step', 'min', 'max', 'align', 'side',
  'position', 'orientation', 'querykey', 'basepath', 'agenttype', 'status',
]);

function looksTranslatable(raw) {
  const s = raw.trim();
  if (s.length < 2) return false;
  if (!/[A-Za-zÀ-￿]/.test(s)) return false;       // must hold a letter
  if (/^https?:\/\//i.test(s)) return false;                 // url
  if (/^[/#.]/.test(s)) return false;                        // path/anchor/css
  if (/^[a-z0-9_]+$/.test(s)) return false;                  // single lc token → id/enum
  if (/^[a-z][a-zA-Z0-9]+$/.test(s) && !/\s/.test(s)) return false; // camelCase id
  if (/^[A-Z0-9_]+$/.test(s)) return false;                  // CONSTANT
  if (/^\{\{.*\}\}$/.test(s)) return false;                  // pure interpolation
  if (/^[\d\s.,:%+\-/()]+$/.test(s)) return false;           // numeric/punct only
  if (/^&[a-z]+;$/.test(s)) return false;                    // html entity
  return true;
}

const report = {}; // file -> [{ line, kind, text }]
let total = 0;

function rel(file) {
  return path.relative(ROOT, file).replace(/\\/g, '/');
}

function isInsideTCall(node) {
  // Skip strings that are arguments to t(...) / i18n.t(...) or assigned to i18nKey.
  let p = node.parent;
  while (p) {
    if (ts.isCallExpression(p)) {
      const ex = p.expression;
      const name = ts.isIdentifier(ex)
        ? ex.text
        : ts.isPropertyAccessExpression(ex)
          ? ex.name.text
          : '';
      if (name === 't' || name === 'useTranslation') return true;
    }
    p = p.parent;
  }
  return false;
}

function walk(file, sourceFile) {
  const add = (node, kind, text) => {
    const t = text.replace(/\s+/g, ' ').trim();
    if (!looksTranslatable(t)) return;
    const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
    (report[rel(file)] ||= []).push({ line: line + 1, kind, text: t });
    total++;
  };

  const visit = (node) => {
    // 1. JSX text
    if (ts.isJsxText(node)) {
      if (node.text && node.text.trim()) add(node, 'jsx-text', node.text);
    }
    // 2. JSX attribute with string literal value
    if (ts.isJsxAttribute(node) && node.initializer) {
      const attr = node.name.getText(sourceFile).toLowerCase();
      let lit = null;
      if (ts.isStringLiteral(node.initializer)) lit = node.initializer;
      else if (
        ts.isJsxExpression(node.initializer) &&
        node.initializer.expression &&
        ts.isStringLiteral(node.initializer.expression)
      ) lit = node.initializer.expression;
      if (lit && !SKIP_ATTRS.has(attr) && UI_ATTRS.has(attr) && !isInsideTCall(lit)) {
        add(lit, `attr:${attr}`, lit.text);
      }
    }
    // 3b. Default parameter value: function X({ cancelLabel = 'Cancel' }) /
    //     function f(prefix = 'Updated'). The extractor historically missed
    //     this class, leaking English into shared components (FormDialog,
    //     FilterBar, LastUpdated). Only flag user-facing prose (heuristic).
    if (
      (ts.isParameter(node) || ts.isBindingElement(node)) &&
      node.initializer &&
      ts.isStringLiteral(node.initializer) &&
      !isInsideTCall(node.initializer)
    ) {
      add(node.initializer, 'param-default', node.initializer.text);
    }
    // 3c. const/let string initializer rendered to users (e.g.
    //     const message = 'Network error...'). High-noise (also catches
    //     technical/enum consts) so opt-in via --consts for deep audits.
    if (
      SCAN_CONSTS &&
      ts.isVariableDeclaration(node) &&
      node.initializer &&
      ts.isStringLiteral(node.initializer) &&
      !isInsideTCall(node.initializer)
    ) {
      add(node.initializer, 'const-string', node.initializer.text);
    }
    // 3. Object-literal property: { title: 'X' } / { message: 'Y' }
    if (ts.isPropertyAssignment(node)) {
      const key = (ts.isIdentifier(node.name) || ts.isStringLiteral(node.name))
        ? node.name.text.toLowerCase()
        : '';
      const init = node.initializer;
      if (
        key && UI_OBJ_KEYS.has(key) &&
        init && (ts.isStringLiteral(init) ||
          (ts.isNoSubstitutionTemplateLiteral && ts.isNoSubstitutionTemplateLiteral(init))) &&
        !isInsideTCall(init)
      ) {
        add(init, `obj:${key}`, init.text);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
}

// Dev-only files are never shipped to users → exclude from the shippable
// count. Pass --all to include them.
const INCLUDE_DEV = process.argv.includes('--all');
// const-string scanning is high-noise (catches technical/enum consts too),
// opt-in for deep audits via --consts.
const SCAN_CONSTS = process.argv.includes('--consts');
const isDevOnly = (name) => /(\.stories\.|\.test\.|\.spec\.)/.test(name) || name.endsWith('.d.ts');

function collect(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!INCLUDE_DEV && entry.name === '__tests__') continue;
      collect(full);
    } else if (entry.name.endsWith('.tsx')) {
      if (!INCLUDE_DEV && isDevOnly(entry.name)) continue;
      const code = fs.readFileSync(full, 'utf8');
      const sf = ts.createSourceFile(full, code, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
      walk(full, sf);
    }
  }
}

collect(SRC);

fs.writeFileSync(OUT, JSON.stringify({ total, files: report }, null, 2));

// ── Ranked summary ─────────────────────────────────────────────────────
const entries = Object.entries(report).map(([f, arr]) => [f, arr.length]).sort((a, b) => b[1] - a[1]);
const pageEntries = entries.filter(([f]) => f.startsWith('src/pages/'));
const compEntries = entries.filter(([f]) => f.startsWith('src/components/'));

const byFeature = {};
for (const [f, n] of pageEntries) {
  const m = f.match(/^src\/pages\/([^/]+)\//);
  const k = m ? m[1] : '(root)';
  byFeature[k] = (byFeature[k] || 0) + n;
}

console.log(`\n=== i18n hardcoded-string inventory ===`);
console.log(`total strings: ${total}`);
console.log(`files with strings: ${entries.length}  (pages: ${pageEntries.length}, components: ${compEntries.length}, other: ${entries.length - pageEntries.length - compEntries.length})`);
console.log(`\n--- top 25 files by string count ---`);
for (const [f, n] of entries.slice(0, 25)) console.log(`${String(n).padStart(4)}  ${f}`);
console.log(`\n--- pages by feature area (rollup) ---`);
for (const [k, n] of Object.entries(byFeature).sort((a, b) => b[1] - a[1])) {
  console.log(`${String(n).padStart(5)}  pages/${k}`);
}
console.log(`\nfull report → ${OUT}`);
