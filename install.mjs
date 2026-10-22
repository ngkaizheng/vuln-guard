#!/usr/bin/env node
// Installs the vuln-check / vuln-setup / vuln-fix skills. Zero dependencies, works on Windows/macOS/Linux.
//
//   node install.mjs                      personal: ~/.claude/skills  (Claude Code + VS Code Copilot)
//   node install.mjs --copilot            personal: also ~/.copilot/skills (Copilot CLI / other Copilot surfaces)
//   node install.mjs --project <repo>     team: <repo>/.claude/skills  (commit it; Claude Code + VS Code Copilot)
//   node install.mjs --project <repo> --github   team: <repo>/.github/skills (GitHub Copilot cloud agent)
//   node install.mjs --target <dir>       any skills folder
//   add --uninstall to remove instead

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const SKILLS = ['vuln-check', 'vuln-setup', 'vuln-fix'];
const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const flag = (f) => args.includes(f);
const val = (f) => { const i = args.indexOf(f); return i >= 0 ? args[i + 1] : null; };

if (flag('-h') || flag('--help')) {
  console.log(fs.readFileSync(fileURLToPath(import.meta.url), 'utf8').split('\n').slice(1, 10).map((l) => l.replace(/^\/\/ ?/, '')).join('\n'));
  process.exit(0);
}

const targets = [];
if (val('--target')) targets.push(path.resolve(val('--target')));
else if (val('--project')) {
  const repo = path.resolve(val('--project'));
  if (!fs.existsSync(repo)) { console.error(`Not found: ${repo}`); process.exit(1); }
  targets.push(path.join(repo, flag('--github') ? '.github' : '.claude', 'skills'));
} else {
  targets.push(path.join(os.homedir(), '.claude', 'skills'));
  if (flag('--copilot')) targets.push(path.join(os.homedir(), '.copilot', 'skills'));
}

for (const t of targets) {
  for (const s of SKILLS) {
    const dest = path.join(t, s);
    if (flag('--uninstall')) {
      if (fs.existsSync(dest)) { fs.rmSync(dest, { recursive: true, force: true }); console.log(`removed  ${dest}`); }
      continue;
    }
    const src = path.join(here, 'skills', s);
    if (!fs.existsSync(path.join(src, 'SKILL.md'))) { console.error(`Missing ${src}/SKILL.md — run install.mjs from the vuln-guard repo folder.`); process.exit(1); }
    fs.rmSync(dest, { recursive: true, force: true });
    fs.mkdirSync(t, { recursive: true });
    fs.cpSync(src, dest, { recursive: true });
    console.log(`installed ${dest}`);
  }
}

if (!flag('--uninstall')) {
  console.log(`\nDone. Restart Claude Code / reload VS Code, then try: "check this project for vulnerabilities".`);
  if (val('--project')) console.log('Commit the skills folder so your team gets them too.');
}
