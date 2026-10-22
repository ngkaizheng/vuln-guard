#!/usr/bin/env node
// Repo checks that tests don't cover. Zero dependencies.
//   node scripts/validate.mjs
// - every skills/<name>/SKILL.md has frontmatter `name` = folder name and a usable `description`
// - every relative link in the skills and top-level docs points at a file that exists
// - plugin / marketplace versions match the scanner's TOOL_VERSION
// - the scanner imports nothing but Node built-ins (the "nothing to install" promise)

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const errors = [];
const fail = (msg) => errors.push(msg);
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');

// ── skills ──
const skills = fs.readdirSync(path.join(root, 'skills'), { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name);
if (!skills.length) fail('no skills found under skills/');
for (const s of skills) {
  const file = `skills/${s}/SKILL.md`;
  if (!fs.existsSync(path.join(root, file))) { fail(`${file} missing`); continue; }
  const fm = read(file).match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!fm) { fail(`${file}: no YAML frontmatter`); continue; }
  const field = (k) => (fm[1].match(new RegExp(`^${k}:\\s*(.+)$`, 'm')) || [])[1]?.trim();
  const name = field('name'), desc = field('description');
  if (name !== s) fail(`${file}: name "${name}" must equal the folder name "${s}"`);
  if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(name || '') || name.length > 64) fail(`${file}: name must be kebab-case, max 64 chars`);
  if (!desc) fail(`${file}: description missing`);
  else {
    if (desc.length > 1024) fail(`${file}: description is ${desc.length} chars (max 1024)`);
    if (!/^["']/.test(desc) && /: | #/.test(desc)) fail(`${file}: unquoted description contains ": " or " #", which breaks YAML — quote it or reword`);
    if (!/\buse (it )?when\b/i.test(desc)) fail(`${file}: description should say when to use the skill ("Use when …") so agents trigger it`);
  }
}

// ── links ──
const docs = ['README.md', 'CONTRIBUTING.md', 'SECURITY.md', 'CHANGELOG.md',
  ...skills.flatMap((s) => walk(`skills/${s}`).filter((f) => f.endsWith('.md')))];
function walk(dir) {
  return fs.readdirSync(path.join(root, dir), { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(`${dir}/${e.name}`) : [`${dir}/${e.name}`]));
}
for (const doc of docs) {
  if (!fs.existsSync(path.join(root, doc))) { fail(`${doc} missing`); continue; }
  const text = read(doc).replace(/```[\s\S]*?```/g, ''); // links inside code blocks are examples
  for (const m of text.matchAll(/\]\(([^)\s]+)\)/g)) {
    const target = m[1].split('#')[0];
    if (!target || /^[a-z]+:/i.test(target)) continue; // anchors, http:, mailto:
    if (!fs.existsSync(path.join(root, path.dirname(doc), decodeURI(target)))) fail(`${doc}: broken link ${m[1]}`);
  }
}

// ── versions ──
const scan = read('skills/vuln-check/scripts/scan.mjs');
const toolVersion = (scan.match(/const TOOL_VERSION = '([^']+)'/) || [])[1];
const plugin = JSON.parse(read('.claude-plugin/plugin.json'));
const market = JSON.parse(read('.claude-plugin/marketplace.json'));
for (const [where, v] of [['plugin.json', plugin.version], ...market.plugins.map((p) => [`marketplace.json (${p.name})`, p.version])]) {
  if (v !== toolVersion) fail(`${where} version ${v} ≠ scan.mjs TOOL_VERSION ${toolVersion}`);
}
if (!read('CHANGELOG.md').includes(`## ${toolVersion}`)) fail(`CHANGELOG.md has no "## ${toolVersion}" section`);

// ── zero dependencies ──
for (const f of ['skills/vuln-check/scripts/scan.mjs', 'install.mjs']) {
  for (const m of read(f).matchAll(/^\s*import\s[^'"]*['"]([^'"]+)['"]/gm)) {
    if (!m[1].startsWith('node:')) fail(`${f}: imports "${m[1]}" — only node: built-ins are allowed`);
  }
}
if (fs.existsSync(path.join(root, 'package.json')) && JSON.parse(read('package.json')).dependencies) fail('package.json must not declare dependencies');

if (errors.length) { console.error(errors.map((e) => `✗ ${e}`).join('\n')); process.exit(1); }
console.log(`✓ ${skills.length} skills, ${docs.length} docs, version ${toolVersion}, zero dependencies`);
