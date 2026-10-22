#!/usr/bin/env node
// vuln-guard scan engine
// Finds published, still-unfixed vulnerabilities in a project's dependencies,
// runtimes and container base images. Zero dependencies, Node.js >= 18.
//
//   node scan.mjs [--path <dir>] [options]
//
// Data sources: OSV.dev (all ecosystems), CISA KEV (actively exploited),
// FIRST EPSS (exploit probability), endoflife.date (runtime patch/EOL),
// plus `npm audit` and `dotnet list package --vulnerable` when available.
// Only package names + versions leave the machine, never source code.

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';

const TOOL_VERSION = '1.0.0';

// ───────────────────────────── CLI ─────────────────────────────

const HELP = `vuln-guard scan ${TOOL_VERSION}

Usage: node scan.mjs [options]

  --path <dir>        Project root to scan (default: current directory)
  --out <dir>         Where to write report.md / report.json
                      (default: <path>/.vuln-guard/reports)
  --config <file>     Config file (default: <path>/.vuln-guard/config.json)
  --json              Print the JSON report to stdout instead of markdown
  --sarif <file>      Also write SARIF 2.1.0 (for GitHub code scanning upload)
  --quiet             Print only the one-line summary
  --offline           No network: inventory + local tools only
  --no-native         Skip npm audit / dotnet list package
  --no-runtime        Skip runtime / base-image / EOL checks
  --no-dev            Ignore dev-only dependencies
  --no-epss           Skip EPSS lookups
  --fail-on <level>   Exit 1 if any finding at/above: kev|critical|high|moderate|low
                      (default: never fail)
  --max-depth <n>     Directory depth to search (default 8)
  -h, --help          Show this help

Behind a corporate proxy (Node >= 22.21 / 24.5):
  set NODE_USE_ENV_PROXY=1 and HTTPS_PROXY=http://proxy:port
  TLS inspection: set NODE_EXTRA_CA_CERTS=<path to company root CA .pem>
`;

function parseArgs(argv) {
  const o = {
    path: process.cwd(), out: null, config: null, sarif: null, json: false, quiet: false,
    offline: false, native: true, runtime: true, dev: true, epss: true,
    failOn: 'none', maxDepth: 8,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => { const v = argv[++i]; if (v === undefined) die(`Missing value for ${a}`); return v; };
    switch (a) {
      case '--path': o.path = next(); break;
      case '--out': o.out = next(); break;
      case '--config': o.config = next(); break;
      case '--json': o.json = true; break;
      case '--sarif': o.sarif = next(); break;
      case '--quiet': o.quiet = true; break;
      case '--offline': o.offline = true; break;
      case '--no-native': o.native = false; break;
      case '--no-runtime': o.runtime = false; break;
      case '--no-dev': o.dev = false; break;
      case '--no-epss': o.epss = false; break;
      case '--fail-on': o.failOn = next().toLowerCase(); break;
      case '--max-depth': o.maxDepth = parseInt(next(), 10) || 8; break;
      case '-h': case '--help': process.stdout.write(HELP); process.exit(0);
      default: die(`Unknown option ${a}\n\n${HELP}`);
    }
  }
  o.path = path.resolve(o.path);
  if (!fs.existsSync(o.path)) die(`Path not found: ${o.path}`);
  o.out = path.resolve(o.out || path.join(o.path, '.vuln-guard', 'reports'));
  o.config = path.resolve(o.config || path.join(o.path, '.vuln-guard', 'config.json'));
  if (o.sarif) o.sarif = path.resolve(o.sarif);
  const levels = ['none', 'kev', 'critical', 'high', 'moderate', 'low'];
  if (!levels.includes(o.failOn)) die(`--fail-on must be one of ${levels.join(', ')}`);
  return o;
}

function die(msg) { process.stderr.write(msg + '\n'); process.exit(2); }

const notes = [];
const note = (level, msg) => notes.push({ level, msg });

// ───────────────────────────── helpers ─────────────────────────────

const rel = (p) => path.relative(OPTS.path, p).split(path.sep).join('/') || '.';
const readText = (p) => { try { return fs.readFileSync(p, 'utf8').replace(/^﻿/, ''); } catch { return null; } };
const readJson = (p) => { const t = readText(p); if (t == null) return null; try { return JSON.parse(t); } catch { note('warn', `Could not parse JSON: ${rel(p)}`); return null; } };

function globToRegex(g) {
  return new RegExp('^' + g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'i');
}

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (i < items.length) { const idx = i++; out[idx] = await fn(items[idx], idx); }
  });
  await Promise.all(workers);
  return out;
}

function which(cmd) {
  const r = spawnSync(process.platform === 'win32' ? 'where' : 'which', [cmd], { encoding: 'utf8' });
  return r.status === 0;
}

function run(cmd, args, cwd, timeoutMs = 180000) {
  // Windows needs a shell only for npm (npm.cmd). Never use one for commands that get
  // repo file paths as arguments: spaces would split them and `&` in a file name would run code.
  const r = spawnSync(cmd, args, {
    cwd, encoding: 'utf8', timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024,
    shell: process.platform === 'win32' && cmd === 'npm', windowsHide: true,
  });
  return { code: r.status, stdout: r.stdout || '', stderr: r.stderr || '', error: r.error };
}

// Version comparison good enough for semver, NuGet, PyPI release versions, Maven.
function cmpVer(a, b) {
  const norm = (v) => String(v).trim().replace(/^[v=]+/i, '');
  const split = (v) => {
    const s = norm(v);
    const m = s.match(/^([0-9][0-9.]*)(.*)$/);
    if (!m) return { main: [s], pre: '' };
    return { main: m[1].replace(/\.$/, '').split('.'), pre: m[2].replace(/^[-+._]/, '').split('+')[0] };
  };
  const A = split(a), B = split(b);
  const n = Math.max(A.main.length, B.main.length);
  for (let i = 0; i < n; i++) {
    const x = A.main[i] ?? '0', y = B.main[i] ?? '0';
    const nx = Number(x), ny = Number(y);
    if (!Number.isNaN(nx) && !Number.isNaN(ny)) { if (nx !== ny) return nx < ny ? -1 : 1; }
    else if (x !== y) return x < y ? -1 : 1;
  }
  const preRank = (p) => {
    if (!p) return null;
    const l = p.toLowerCase();
    if (/^(final|ga|release|sp\d*|post\d*|p\d+|r\d+)$/.test(l)) return 'post';
    return l;
  };
  const pa = preRank(A.pre), pb = preRank(B.pre);
  if (pa === pb) return 0;
  if (pa === null) return pb === 'post' ? -1 : 1;
  if (pb === null) return pa === 'post' ? 1 : -1;
  if (pa === 'post') return 1;
  if (pb === 'post') return -1;
  return pa < pb ? -1 : 1;
}

const majorOf = (v) => {
  const p = String(v).replace(/^[v=]+/i, '').split(/[.\-+]/).map(Number);
  // 0.x: a minor bump is breaking
  return p[0] === 0 ? `0.${p[1] ?? 0}` : String(p[0]);
};
// Go never bumps its major; a new 1.x line is the "breaking" move for the toolchain
const isMajorMove = (pkg, to) => Boolean(to) && (pkg.eco === ECO.go && pkg.name === 'stdlib'
  ? to.split('.').slice(0, 2).join('.') !== pkg.version.split('.').slice(0, 2).join('.')
  : majorOf(to) !== majorOf(pkg.version));

// ───────────────────────────── config ─────────────────────────────

function loadConfig() {
  const c = fs.existsSync(OPTS.config) ? readJson(OPTS.config) || {} : {};
  return {
    ignore: Array.isArray(c.ignore) ? c.ignore : [],
    private: (Array.isArray(c.private) ? c.private : []).map(globToRegex),
    skipDirs: new Set([...(Array.isArray(c.skipDirs) ? c.skipDirs : [])]),
  };
}

// ───────────────────────────── inventory ─────────────────────────────

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.hg', '.svn', 'bin', 'dist', 'build', 'out', '.next', '.nuxt',
  '.output', '.svelte-kit', '.angular', '.turbo', '.cache', 'vendor', '.venv', 'venv', 'env',
  '__pycache__', '.tox', 'target', 'packages', '.vuln-guard', 'coverage', '.idea', '.vs',
  '.vscode', '.gradle', 'Pods', 'DerivedData', 'TestResults', 'wwwroot',
]);

/** @type {Map<string, any>} */
const PKGS = new Map();          // key eco|name|version → package record
const DIRECT = new Map();        // dir|eco → Set(names) from manifests
const RUNTIMES = [];             // declared runtimes / base images
const FILES_SEEN = [];

const ECO = { npm: 'npm', nuget: 'NuGet', pypi: 'PyPI', go: 'Go', cargo: 'crates.io', gem: 'RubyGems', composer: 'Packagist', maven: 'Maven', pub: 'Pub' };

function nameKey(eco, name) {
  if (eco === ECO.nuget) return name.toLowerCase();
  if (eco === ECO.pypi) return name.toLowerCase().replace(/[-_.]+/g, '-');
  return name;
}

function addPkg(eco, name, version, src) {
  if (!name || !version) return;
  version = String(version).trim();
  if (eco === ECO.composer || eco === ECO.go) version = version.replace(/^v/, '');
  if (!/^[0-9]/.test(version)) {
    // ranges / git refs / workspace links cannot be checked exactly
    if (!/^(file:|link:|workspace:|git|http|github:|portal:|patch:)/.test(version)) src.unpinned = true;
    if (src.unpinned) recordUnpinned(eco, name, version, src);
    return;
  }
  const key = `${eco}|${nameKey(eco, name)}|${version}`;
  let p = PKGS.get(key);
  if (!p) { p = { eco, name, version, sources: [], direct: false, devOnly: true }; PKGS.set(key, p); }
  if (!p.sources.some((s) => s.file === src.file)) p.sources.push(src);
  if (src.direct) p.direct = true;
  if (!src.dev) p.devOnly = false;
}

const UNPINNED = [];
function recordUnpinned(eco, name, spec, src) {
  if (UNPINNED.length < 200) UNPINNED.push({ eco, name, spec, file: src.file });
}

function walk(dir, depth, cfg, visit) {
  if (depth > OPTS.maxDepth) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === 'obj') { // only want NuGet's resolved graph from obj/
        const assets = path.join(full, 'project.assets.json');
        if (fs.existsSync(assets)) visit(assets, 'project.assets.json');
        continue;
      }
      if (SKIP_DIRS.has(e.name) || cfg.skipDirs.has(e.name) || (e.name.startsWith('.') && e.name !== '.github' && e.name !== '.config')) continue;
      walk(full, depth + 1, cfg, visit);
    } else if (e.isFile()) {
      visit(full, e.name);
    }
  }
}

function collect(cfg) {
  const byDir = new Map(); // dir → [{file, base}]
  walk(OPTS.path, 0, cfg, (file, base) => {
    const d = base === 'project.assets.json' ? path.dirname(path.dirname(file)) : path.dirname(file);
    if (!byDir.has(d)) byDir.set(d, []);
    byDir.get(d).push({ file, base });
  });

  // shallow directories first (root manifests before workspace children),
  // and central NuGet versions before any project that relies on them
  const ordered = [...byDir.entries()].sort((a, b) => a[0].split(path.sep).length - b[0].split(path.sep).length || a[0].localeCompare(b[0]));
  for (const [, files] of ordered) for (const f of files) if (f.base === 'Directory.Packages.props') parseCentralPackages(f.file);

  for (const [dir, files] of ordered) {
    const has = (b) => files.find((f) => f.base === b);
    const bases = new Set(files.map((f) => f.base));

    // ── npm family ──
    const pkgJson = has('package.json');
    let pj = null;
    if (pkgJson) {
      pj = readJson(pkgJson.file);
      if (pj) {
        const direct = new Set(Object.keys({ ...pj.dependencies, ...pj.optionalDependencies, ...pj.peerDependencies }));
        const devSet = new Set(Object.keys(pj.devDependencies || {}));
        DIRECT.set(`${dir}|npm`, { direct, dev: devSet });
        detectNodeEngine(pj, pkgJson.file);
      }
    }
    const npmLock = has('package-lock.json') || has('npm-shrinkwrap.json');
    const yarnLock = has('yarn.lock');
    const pnpmLock = has('pnpm-lock.yaml');
    if (npmLock) parseNpmLock(npmLock.file, dir);
    if (yarnLock) parseYarnLock(yarnLock.file, dir);
    if (pnpmLock) parsePnpmLock(pnpmLock.file, dir);
    const bunLock = has('bun.lock');
    if (bunLock) parseBunLock(bunLock.file, dir);
    else if (bases.has('bun.lockb')) note('warn', `${rel(dir)}: binary bun.lockb is not readable — run \`bun install --save-text-lockfile\` (Bun ≥ 1.1.39) to get bun.lock.`);
    if (pj && !npmLock && !yarnLock && !pnpmLock && !bunLock && !isWorkspaceChild(dir)) {
      note('warn', `${rel(pkgJson.file)} has no lockfile — exact versions unknown, only pinned versions checked. Run npm install / pnpm install to create one.`);
      for (const [n, v] of Object.entries({ ...pj.dependencies })) addPkg(ECO.npm, n, v, { file: rel(pkgJson.file), manager: 'npm', direct: true, dev: false, dir });
      for (const [n, v] of Object.entries({ ...pj.devDependencies })) addPkg(ECO.npm, n, v, { file: rel(pkgJson.file), manager: 'npm', direct: true, dev: true, dir });
    }

    // ── NuGet ──
    const projFiles = files.filter((f) => /\.(cs|fs|vb)proj$/i.test(f.base));
    const assets = has('project.assets.json');
    const nugetLock = has('packages.lock.json');
    for (const p of projFiles) parseProjFile(p.file, dir, Boolean(assets || nugetLock));
    if (assets) parseAssets(assets.file, dir, projFiles[0]?.file);
    else if (nugetLock) parseNugetLock(nugetLock.file, dir, projFiles[0]?.file);
    else if (projFiles.length && projFiles.some((p) => /PackageReference/.test(readText(p.file) || ''))) {
      note('warn', `${rel(projFiles[0].file)}: no obj/project.assets.json or packages.lock.json — only direct packages checked. Run \`dotnet restore\` first to include transitive packages.`);
    }
    const pkgConfig = has('packages.config');
    if (pkgConfig) parsePackagesConfig(pkgConfig.file, dir);
    for (const f of files) if (/\.csproj$|\.vbproj$/i.test(f.base)) detectDotnetFramework(f.file);
    const gj = has('global.json');
    if (gj) { const g = readJson(gj.file); if (g?.sdk?.version) RUNTIMES.push({ product: 'dotnet', kind: 'SDK (global.json)', version: g.sdk.version, file: rel(gj.file), pinned: false, sdk: true }); }

    // ── Python ──
    for (const f of files) if (/^requirements.*\.txt$/i.test(f.base) || /^constraints.*\.txt$/i.test(f.base)) parseRequirements(f.file, dir);
    const poetry = has('poetry.lock'); if (poetry) parseTomlPackages(poetry.file, dir, ECO.pypi, 'poetry');
    const uv = has('uv.lock'); if (uv) parseTomlPackages(uv.file, dir, ECO.pypi, 'uv');
    const pipenv = has('Pipfile.lock'); if (pipenv) parsePipfileLock(pipenv.file, dir);
    const pyv = has('.python-version'); if (pyv) declareRuntime('python', (readText(pyv.file) || '').trim().split(/\s+/)[0], pyv.file, 'Python (.python-version)');

    // ── Go / Rust / Ruby / PHP / Java / Dart ──
    const gomod = has('go.mod'); if (gomod) parseGoMod(gomod.file, dir);
    const cargo = has('Cargo.lock'); if (cargo) parseTomlPackages(cargo.file, dir, ECO.cargo, 'cargo', true);
    const gem = has('Gemfile.lock'); if (gem) parseGemfileLock(gem.file, dir);
    const rbv = has('.ruby-version'); if (rbv) declareRuntime('ruby', (readText(rbv.file) || '').trim(), rbv.file, 'Ruby (.ruby-version)');
    const comp = has('composer.lock'); if (comp) parseComposerLock(comp.file, dir);
    const pom = has('pom.xml'); if (pom) parsePom(pom.file, dir);
    const gl = has('gradle.lockfile'); if (gl) parseGradleLock(gl.file, dir);
    if (!gl && (bases.has('build.gradle') || bases.has('build.gradle.kts'))) note('warn', `${rel(dir)}: Gradle project without gradle.lockfile — run \`gradle dependencies --write-locks\` to make it scannable.`);
    const pub = has('pubspec.lock'); if (pub) parsePubspecLock(pub.file, dir);

    // ── runtimes / images ──
    const nvm = has('.nvmrc') || has('.node-version');
    if (nvm) declareRuntime('nodejs', (readText(nvm.file) || '').trim().replace(/^v/, ''), nvm.file, `Node.js (${nvm.base})`);
    const tv = has('.tool-versions'); if (tv) parseToolVersions(tv.file);
    for (const f of files) {
      if (/^Dockerfile/i.test(f.base) || /\.dockerfile$/i.test(f.base) || /^Containerfile/i.test(f.base)) parseDockerfile(f.file);
      if (/^(docker-)?compose.*\.ya?ml$/i.test(f.base)) parseCompose(f.file);
    }
  }
}

function isWorkspaceChild(dir) {
  // a package.json inside a workspace is covered by the root lockfile
  let d = path.dirname(dir);
  while (d.startsWith(OPTS.path) && d !== dir) {
    for (const lf of ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock']) if (fs.existsSync(path.join(d, lf))) return true;
    if (d === OPTS.path) break;
    d = path.dirname(d);
  }
  return false;
}

// npm package-lock v1/v2/v3
function parseNpmLock(file, dir) {
  const j = readJson(file); if (!j) return;
  FILES_SEEN.push(rel(file));
  const directInfo = DIRECT.get(`${dir}|npm`);
  if (j.packages) {
    for (const [k, v] of Object.entries(j.packages)) {
      if (!k || v.link || !v.version) continue;
      const idx = k.lastIndexOf('node_modules/');
      if (idx < 0) continue; // workspace package itself
      const name = v.name || k.slice(idx + 'node_modules/'.length);
      const top = k === `node_modules/${name}`;
      const direct = top && Boolean(directInfo && (directInfo.direct.has(name) || directInfo.dev.has(name)));
      addPkg(ECO.npm, name, v.version, { file: rel(file), manager: 'npm', direct, dev: Boolean(v.dev || v.devOptional), dir });
    }
  } else if (j.dependencies) {
    const recurse = (deps, depth) => {
      for (const [name, v] of Object.entries(deps)) {
        if (v.version && !String(v.version).startsWith('file:')) {
          addPkg(ECO.npm, name, v.version, { file: rel(file), manager: 'npm', direct: depth === 0 && Boolean(directInfo && (directInfo.direct.has(name) || directInfo.dev.has(name))), dev: Boolean(v.dev), dir });
        }
        if (v.dependencies) recurse(v.dependencies, depth + 1);
      }
    };
    recurse(j.dependencies, 0);
  }
}

function yarnNameFromSpec(spec) {
  spec = spec.trim().replace(/^"|"$/g, '');
  const at = spec.indexOf('@', 1);
  return at > 0 ? spec.slice(0, at) : spec;
}

function parseYarnLock(file, dir) {
  const t = readText(file); if (!t) return;
  FILES_SEEN.push(rel(file));
  const berry = /__metadata:/.test(t);
  const directInfo = DIRECT.get(`${dir}|npm`);
  let names = null;
  for (const line of t.split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    if (!/^\s/.test(line) && line.trimEnd().endsWith(':')) {
      const header = line.trimEnd().slice(0, -1);
      if (header === '__metadata') { names = null; continue; }
      names = [...new Set(header.split(/,\s*/).map(yarnNameFromSpec))];
      if (header.includes('@workspace:') || header.includes('@link:') || header.includes('@portal:')) names = null;
      continue;
    }
    const m = line.match(/^\s+version:?\s+"?([^"\s]+)"?\s*$/);
    if (m && names) {
      if (m[1].startsWith('0.0.0-use.local')) { names = null; continue; }
      for (const n of names) {
        const isDirect = Boolean(directInfo && (directInfo.direct.has(n) || directInfo.dev.has(n)));
        addPkg(ECO.npm, n, m[1], { file: rel(file), manager: berry ? 'yarn-berry' : 'yarn', direct: isDirect, dev: Boolean(directInfo && directInfo.dev.has(n) && !directInfo.direct.has(n)), dir });
      }
      names = null;
    }
  }
}

function parsePnpmLock(file, dir) {
  const t = readText(file); if (!t) return;
  FILES_SEEN.push(rel(file));
  const directInfo = DIRECT.get(`${dir}|npm`);
  const lockVer = parseFloat((t.match(/^lockfileVersion:\s*['"]?([\d.]+)/m) || [])[1] || '9');
  let section = null;
  for (const line of t.split(/\r?\n/)) {
    const top = line.match(/^([a-zA-Z]+):\s*$/);
    if (top) { section = top[1]; continue; }
    if (section !== 'packages' && section !== 'snapshots') continue;
    const m = line.match(/^ {2}['"]?([^'"\s].*?)['"]?:\s*$/);
    if (!m) continue;
    let key = m[1].replace(/^\//, '');
    let name, version;
    if (lockVer < 6) { // v5: /name/1.2.3_peer@x or /@scope/name/1.2.3
      key = key.replace(/_.*$/, '');
      const slash = key.lastIndexOf('/'); if (slash <= 0) continue;
      name = key.slice(0, slash); version = key.slice(slash + 1);
    } else { // v6+/v9: name@1.2.3(peer@x)
      key = key.replace(/\(.*$/, '');
      const at = key.lastIndexOf('@'); if (at <= 0) continue;
      name = key.slice(0, at); version = key.slice(at + 1);
    }
    if (!/^[0-9]/.test(version)) continue;
    const isDirect = Boolean(directInfo && (directInfo.direct.has(name) || directInfo.dev.has(name)));
    addPkg(ECO.npm, name, version, { file: rel(file), manager: 'pnpm', direct: isDirect, dev: Boolean(directInfo && directInfo.dev.has(name) && !directInfo.direct.has(name)), dir });
  }
}

// bun.lock (Bun ≥ 1.2 text lockfile): JSON with trailing commas.
// packages: { "<path>": ["name@version", registry, { deps }, integrity] }
function parseBunLock(file, dir) {
  const t = readText(file); if (!t) return;
  let j;
  try { j = JSON.parse(t.replace(/,(\s*[}\]])/g, '$1')); } catch { note('warn', `Could not parse ${rel(file)}`); return; }
  FILES_SEEN.push(rel(file));
  const directInfo = DIRECT.get(`${dir}|npm`);
  const rootWs = j.workspaces?.[''] || {};
  const devNames = new Set(Object.keys(rootWs.devDependencies || {}));
  const prodNames = new Set(Object.keys({ ...rootWs.dependencies, ...rootWs.optionalDependencies, ...rootWs.peerDependencies }));
  for (const [key, v] of Object.entries(j.packages || {})) {
    if (!Array.isArray(v) || typeof v[0] !== 'string') continue;
    const at = v[0].lastIndexOf('@'); if (at <= 0) continue;
    const name = v[0].slice(0, at), version = v[0].slice(at + 1);
    const top = key === name; // nested copies are keyed "parent/name"
    const direct = top && (prodNames.has(name) || devNames.has(name) || Boolean(directInfo && (directInfo.direct.has(name) || directInfo.dev.has(name))));
    addPkg(ECO.npm, name, version, { file: rel(file), manager: 'bun', direct, dev: top && devNames.has(name) && !prodNames.has(name), dir });
  }
}

// ── NuGet ──
const CENTRAL = new Map(); // lowercased name → { version, file }

function parseCentralPackages(file) {
  const t = readText(file); if (!t) return;
  FILES_SEEN.push(rel(file));
  const props = parseMsbuildProps(t);
  for (const m of t.matchAll(/<PackageVersion\b([^>]*?)\/?>/g)) {
    const a = attrs(m[1]);
    const name = a.include || a.update; const v = resolveProp(a.version, props);
    if (name && v) CENTRAL.set(name.toLowerCase(), { version: v, file: rel(file) });
  }
}

function attrs(s) {
  const o = {};
  for (const m of s.matchAll(/([\w:.-]+)\s*=\s*"([^"]*)"/g)) o[m[1].toLowerCase()] = m[2];
  return o;
}

function parseMsbuildProps(t) {
  const o = {};
  for (const block of t.matchAll(/<PropertyGroup[^>]*>([\s\S]*?)<\/PropertyGroup>/g)) {
    for (const m of block[1].matchAll(/<([\w.]+)>([^<]*)<\/\1>/g)) o[m[1]] = m[2].trim();
  }
  return o;
}

function resolveProp(v, props) {
  if (!v) return v;
  return v.replace(/\$\(([\w.]+)\)/g, (_, k) => props[k] ?? `$(${k})`);
}

function nugetVersion(v) {
  if (!v) return null;
  v = v.trim();
  if (v.includes('$(')) return null;
  const range = v.match(/^[[(]\s*([^,\])]*)/);
  if (range) v = range[1].trim();
  return v || null;
}

const PROJ_DIRECT = new Map(); // dir → { proj, names:Set, central:Set }

function parseProjFile(file, dir, hasResolvedGraph) {
  const t = readText(file); if (!t) return;
  FILES_SEEN.push(rel(file));
  const props = parseMsbuildProps(t);
  const names = new Set();
  const usesCentral = /ManagePackageVersionsCentrally>\s*true/i.test(t) || CENTRAL.size > 0;
  for (const m of t.matchAll(/<PackageReference\b([^>]*?)(?:\/>|>([\s\S]*?)<\/PackageReference>)/g)) {
    const a = attrs(m[1]);
    const name = a.include || a.update; if (!name) continue;
    names.add(name.toLowerCase());
    let v = a.version || a.versionoverride || (m[2] && (m[2].match(/<Version>([^<]+)<\/Version>/) || [])[1]);
    v = resolveProp(v, props);
    let fromCentral = false;
    if (!v && CENTRAL.has(name.toLowerCase())) { v = CENTRAL.get(name.toLowerCase()).version; fromCentral = true; }
    const ver = nugetVersion(v);
    if (!hasResolvedGraph && ver) addPkg(ECO.nuget, name, ver, { file: rel(file), manager: fromCentral || (usesCentral && !a.version) ? 'nuget-central' : 'nuget', direct: true, dev: false, dir, project: rel(file) });
  }
  PROJ_DIRECT.set(dir, { proj: rel(file), names, central: usesCentral });
  // runtime declaration
  const tfm = (t.match(/<TargetFrameworks?>([^<]+)<\/TargetFrameworks?>/) || [])[1];
  if (tfm) for (const f of tfm.split(';').map((s) => s.trim()).filter(Boolean)) {
    const m = f.match(/^net(?:coreapp)?(\d+)\.(\d+)/i);
    if (m && Number(m[1]) >= 5 || /^netcoreapp/i.test(f)) declareRuntime('dotnet', `${m[1]}.${m[2]}`, file, `.NET (TargetFramework ${f})`, false);
    else if (/^net4\d+/i.test(f)) declareRuntime('dotnetfx', f.replace(/^net(\d)(\d)(\d)?/i, (_, a, b, c) => `${a}.${b}${c ? '.' + c : ''}`), file, `.NET Framework (${f})`, false);
  }
}

function detectDotnetFramework(file) {
  const t = readText(file) || '';
  const m = t.match(/<TargetFrameworkVersion>v([\d.]+)<\/TargetFrameworkVersion>/);
  if (m) declareRuntime('dotnetfx', m[1], file, `.NET Framework (v${m[1]})`, false);
}

function nugetSrc(file, dir, name, direct) {
  const pd = PROJ_DIRECT.get(dir);
  const central = CENTRAL.has(name.toLowerCase()) || Boolean(pd?.central);
  return { file: rel(file), manager: central ? 'nuget-central' : 'nuget', direct, dev: false, dir, project: pd?.proj };
}

function parseAssets(file, dir) {
  const j = readJson(file); if (!j?.libraries) return;
  FILES_SEEN.push(rel(file));
  const directNames = new Set();
  for (const fw of Object.values(j.project?.frameworks || {})) for (const n of Object.keys(fw.dependencies || {})) directNames.add(n.toLowerCase());
  for (const [k, v] of Object.entries(j.libraries)) {
    if (v.type !== 'package') continue;
    const i = k.lastIndexOf('/'); if (i < 0) continue;
    const name = k.slice(0, i), ver = k.slice(i + 1);
    addPkg(ECO.nuget, name, ver, nugetSrc(file, dir, name, directNames.has(name.toLowerCase())));
  }
}

function parseNugetLock(file, dir) {
  const j = readJson(file); if (!j?.dependencies) return;
  FILES_SEEN.push(rel(file));
  for (const deps of Object.values(j.dependencies)) {
    for (const [name, v] of Object.entries(deps)) {
      if (v.type === 'Project' || !v.resolved) continue;
      addPkg(ECO.nuget, name, v.resolved, nugetSrc(file, dir, name, v.type === 'Direct'));
    }
  }
}

function parsePackagesConfig(file, dir) {
  const t = readText(file); if (!t) return;
  FILES_SEEN.push(rel(file));
  for (const m of t.matchAll(/<package\b([^>]*?)\/?>/g)) {
    const a = attrs(m[1]);
    if (a.id && a.version) addPkg(ECO.nuget, a.id, a.version, { file: rel(file), manager: 'nuget-packages-config', direct: true, dev: a.developmentdependency === 'true', dir });
  }
}

// ── Python ──
function parseRequirements(file, dir) {
  const t = readText(file); if (!t) return;
  FILES_SEEN.push(rel(file));
  for (let line of t.split(/\r?\n/)) {
    line = line.replace(/\s+#.*$/, '').trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;
    const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([0-9][^\s;,]*)/);
    if (m) addPkg(ECO.pypi, m[1], m[2], { file: rel(file), manager: 'pip', direct: true, dev: /dev|test/i.test(path.basename(file)), dir });
    else if (/^[A-Za-z0-9]/.test(line)) recordUnpinned(ECO.pypi, line.split(/[<>=!~;\s[]/)[0], line, { file: rel(file) });
  }
}

function parseTomlPackages(file, dir, eco, manager, requireSource = false) {
  const t = readText(file); if (!t) return;
  FILES_SEEN.push(rel(file));
  const blocks = t.split(/^\[\[package\]\]\s*$/m).slice(1);
  for (const b of blocks) {
    const body = b.split(/^\[/m)[0];
    const name = (body.match(/^name\s*=\s*"([^"]+)"/m) || [])[1];
    const version = (body.match(/^version\s*=\s*"([^"]+)"/m) || [])[1];
    if (requireSource && !/^source\s*=/m.test(body)) continue; // workspace crate
    if (manager === 'uv' && /^source\s*=\s*\{\s*(editable|virtual|workspace)/m.test(body)) continue;
    const dev = /^category\s*=\s*"dev"/m.test(body);
    addPkg(eco, name, version, { file: rel(file), manager, direct: false, dev, dir });
  }
}

function parsePipfileLock(file, dir) {
  const j = readJson(file); if (!j) return;
  FILES_SEEN.push(rel(file));
  for (const [sec, dev] of [['default', false], ['develop', true]]) {
    for (const [n, v] of Object.entries(j[sec] || {})) {
      if (v.version) addPkg(ECO.pypi, n, v.version.replace(/^==/, ''), { file: rel(file), manager: 'pipenv', direct: false, dev, dir });
    }
  }
}

// ── Go ──
function parseGoMod(file, dir) {
  const t = readText(file); if (!t) return;
  FILES_SEEN.push(rel(file));
  const goV = (t.match(/^go\s+([\d.]+)/m) || [])[1];
  const tool = (t.match(/^toolchain\s+go([\d.]+)/m) || [])[1];
  if (tool || goV) declareRuntime('go', tool || goV, file, `Go (${tool ? 'toolchain' : 'go directive'})`, Boolean(tool));
  // the Go standard library is compiled into the binary, so its CVEs ship with the app.
  // OSV lists them under Go/"stdlib"; check the declared toolchain (or a full x.y.z go directive).
  const stdlib = tool || (goV && goV.split('.').length >= 3 ? goV : null);
  if (stdlib) addPkg(ECO.go, 'stdlib', stdlib, { file: rel(file), manager: 'go-toolchain', direct: true, dev: false, dir });
  else if (goV) note('info', `${rel(file)}: \`go ${goV}\` without a patch version — Go standard library CVEs not checked. Add \`toolchain go${goV}.N\` or run govulncheck.`);
  const add = (line) => {
    const m = line.trim().match(/^([^\s]+)\s+(v[^\s]+)(\s*\/\/\s*indirect)?/);
    if (m) addPkg(ECO.go, m[1], m[2], { file: rel(file), manager: 'go', direct: !m[3], dev: false, dir });
  };
  for (const blk of t.matchAll(/^require\s*\(([\s\S]*?)^\)/gm)) blk[1].split(/\r?\n/).forEach(add);
  for (const m of t.matchAll(/^require\s+([^(\s].*)$/gm)) add(m[1]);
}

// ── Ruby / PHP / Java / Dart ──
function parseGemfileLock(file, dir) {
  const t = readText(file); if (!t) return;
  FILES_SEEN.push(rel(file));
  let inSpecs = false;
  for (const line of t.split(/\r?\n/)) {
    if (/^\s{2}specs:/.test(line)) { inSpecs = true; continue; }
    if (/^\S/.test(line)) inSpecs = false;
    if (!inSpecs) continue;
    const m = line.match(/^ {4}([^\s(]+) \(([^)]+)\)$/);
    if (m) addPkg(ECO.gem, m[1], m[2].split('-')[0], { file: rel(file), manager: 'bundler', direct: false, dev: false, dir });
  }
  const rv = (t.match(/RUBY VERSION\s+ruby ([\d.]+)/) || [])[1];
  if (rv) declareRuntime('ruby', rv, file, 'Ruby (Gemfile.lock)', true);
}

function parseComposerLock(file, dir) {
  const j = readJson(file); if (!j) return;
  FILES_SEEN.push(rel(file));
  for (const [sec, dev] of [['packages', false], ['packages-dev', true]]) {
    for (const p of j[sec] || []) addPkg(ECO.composer, p.name, p.version, { file: rel(file), manager: 'composer', direct: false, dev, dir });
  }
}

function parsePom(file, dir) {
  const t = readText(file); if (!t) return;
  FILES_SEEN.push(rel(file));
  const props = {};
  const pb = t.match(/<properties>([\s\S]*?)<\/properties>/);
  if (pb) for (const m of pb[1].matchAll(/<([\w.-]+)>([^<]*)<\/\1>/g)) props[m[1]] = m[2].trim();
  props['project.version'] = (t.replace(/<parent>[\s\S]*?<\/parent>/, '').match(/<version>([^<]+)<\/version>/) || [])[1];
  for (const m of t.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const g = (m[1].match(/<groupId>([^<]+)<\/groupId>/) || [])[1];
    const a = (m[1].match(/<artifactId>([^<]+)<\/artifactId>/) || [])[1];
    let v = (m[1].match(/<version>([^<]+)<\/version>/) || [])[1];
    const scope = (m[1].match(/<scope>([^<]+)<\/scope>/) || [])[1];
    if (!g || !a || !v) continue;
    v = v.replace(/\$\{([^}]+)\}/g, (_, k) => props[k] ?? `\${${k}}`);
    if (v.includes('${')) continue;
    addPkg(ECO.maven, `${g}:${a}`, v.replace(/^\[|\]$/g, ''), { file: rel(file), manager: 'maven', direct: true, dev: scope === 'test', dir });
  }
  note('info', `${rel(file)}: Maven — only directly declared versions are checked. For the full tree generate a lockfile or run osv-scanner.`);
}

function parseGradleLock(file, dir) {
  const t = readText(file); if (!t) return;
  FILES_SEEN.push(rel(file));
  for (const line of t.split(/\r?\n/)) {
    const m = line.match(/^([^#:\s]+):([^:\s]+):([^=\s]+)=(.*)$/);
    if (m) addPkg(ECO.maven, `${m[1]}:${m[2]}`, m[3], { file: rel(file), manager: 'gradle', direct: false, dev: m[4].split(',').every((c) => /^test/i.test(c.trim())), dir });
  }
}

function parsePubspecLock(file, dir) {
  const t = readText(file); if (!t) return;
  FILES_SEEN.push(rel(file));
  let name = null, sdk = false, depType = '';
  const flush = (v) => { if (name && !sdk) addPkg(ECO.pub, name, v, { file: rel(file), manager: 'pub', direct: depType.startsWith('direct'), dev: depType === 'direct dev', dir }); };
  for (const line of t.split(/\r?\n/)) {
    const n = line.match(/^ {2}([\w-]+):\s*$/);
    if (n) { name = n[1]; sdk = false; depType = ''; continue; }
    if (/^ {4}source:\s*sdk/.test(line)) sdk = true;
    const d = line.match(/^ {4}dependency:\s*"?([^"]+)"?/); if (d) depType = d[1];
    const v = line.match(/^ {4}version:\s*"?([^"\s]+)"?/); if (v) flush(v[1]);
  }
}

// ── runtimes ──
function declareRuntime(product, version, file, kind, pinned = true) {
  if (!version) return;
  version = String(version).trim().replace(/^v/, '');
  const f = typeof file === 'string' && path.isAbsolute(file) ? rel(file) : file;
  // same runtime declared in many projects (e.g. net10.0 in every .csproj): one row, count the rest
  const same = RUNTIMES.find((r) => r.product === product && r.version === version && r.kind === kind);
  if (same) { if (same.file !== f) same.alsoIn = (same.alsoIn || 0) + 1; return same; }
  // "3.12" or "22" is a line, not a patch level — can't be "behind"
  const r = { product, kind, version, file: f, pinned: pinned && version.split('.').length >= 3 };
  RUNTIMES.push(r);
  return r;
}

function detectNodeEngine(pj, file) {
  const e = pj?.engines?.node;
  if (!e) return;
  const m = String(e).match(/(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (!m) return;
  const r = declareRuntime('nodejs', m[0], file, `Node.js minimum (engines: ${e})`, false);
  if (r) r.minimum = /^\s*(>=|\^|~|>)/.test(String(e));
}

function parseToolVersions(file) {
  const t = readText(file) || '';
  const map = { nodejs: 'nodejs', python: 'python', ruby: 'ruby', golang: 'go', java: null, dotnet: 'dotnet', 'dotnet-core': 'dotnet', php: 'php' };
  for (const line of t.split(/\r?\n/)) {
    const [tool, ver] = line.trim().split(/\s+/);
    if (map[tool] && ver) declareRuntime(map[tool], ver, file, `${tool} (.tool-versions)`);
  }
}

const IMAGE_PRODUCTS = [
  [/^mcr\.microsoft\.com\/dotnet\/(aspnet|runtime|runtime-deps|sdk)$/, 'dotnet'],
  [/^(library\/)?node$/, 'nodejs'], [/^(library\/)?python$/, 'python'], [/^(library\/)?golang$/, 'go'],
  [/^(library\/)?nginx$/, 'nginx'], [/^(library\/)?php$/, 'php'], [/^(library\/)?ruby$/, 'ruby'],
  [/^(library\/)?postgres$/, 'postgresql'], [/^(library\/)?redis$/, 'redis'], [/^(library\/)?mysql$/, 'mysql'],
  [/^(library\/)?mariadb$/, 'mariadb'], [/^(library\/)?mongo$/, 'mongodb'], [/^(library\/)?alpine$/, 'alpine'],
  [/^(library\/)?ubuntu$/, 'ubuntu'], [/^(library\/)?eclipse-temurin$/, 'eclipse-temurin'], [/^(library\/)?httpd$/, 'apache-http-server'],
  [/^(library\/)?tomcat$/, 'tomcat'], [/^mcr\.microsoft\.com\/mssql\/server$/, 'mssqlserver'],
];

function analyseImage(ref, file) {
  if (!ref || ref.includes('$') || ref === 'scratch') return;
  const at = ref.split('@')[0];
  const lastColon = at.lastIndexOf(':');
  const hasTag = lastColon > at.lastIndexOf('/');
  let image = hasTag ? at.slice(0, lastColon) : at;
  const tag = hasTag ? at.slice(lastColon + 1) : 'latest';
  image = image.replace(/^(docker\.io|index\.docker\.io)\//, '');
  const hit = IMAGE_PRODUCTS.find(([re]) => re.test(image));
  if (!hit) return;
  const vm = tag.match(/^(\d+(?:\.\d+){0,3})/);
  if (!vm) {
    RUNTIMES.push({ product: hit[1], kind: `Image ${image}:${tag}`, version: null, file: rel(file), pinned: false, floatingTag: tag });
    return;
  }
  const fullPatch = vm[1].split('.').length >= 3; // 8.0 floats, 8.0.11 is pinned
  RUNTIMES.push({ product: hit[1], kind: `Image ${image}:${tag}`, version: vm[1], file: rel(file), pinned: fullPatch });
}

function parseDockerfile(file) {
  const t = readText(file); if (!t) return;
  FILES_SEEN.push(rel(file));
  const stages = new Set();
  for (const m of t.matchAll(/^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?/gim)) {
    if (!stages.has(m[1].toLowerCase())) analyseImage(m[1], file);
    if (m[2]) stages.add(m[2].toLowerCase());
  }
}

function parseCompose(file) {
  const t = readText(file); if (!t) return;
  for (const m of t.matchAll(/^\s+image:\s*["']?([^"'\s#]+)/gm)) analyseImage(m[1], file);
}

function localRuntimes() {
  const out = [];
  const pk = [...PKGS.values()];
  const usesDotnet = RUNTIMES.some((r) => r.product === 'dotnet') || pk.some((p) => p.eco === ECO.nuget);
  const usesNode = RUNTIMES.some((r) => r.product === 'nodejs') || pk.some((p) => p.eco === ECO.npm);
  if (usesDotnet && which('dotnet')) {
    const r = run('dotnet', ['--list-runtimes'], OPTS.path, 30000);
    const seen = new Map();
    for (const m of r.stdout.matchAll(/^(Microsoft\.(?:NETCore|AspNetCore)\.App)\s+(\S+)/gm)) {
      const cyc = m[2].split('.').slice(0, 2).join('.');
      if (!seen.has(cyc) || cmpVer(m[2], seen.get(cyc)) > 0) seen.set(cyc, m[2]);
    }
    for (const v of seen.values()) out.push({ product: 'dotnet', kind: 'Installed on this machine (dotnet --list-runtimes)', version: v, file: '(local)', pinned: true, local: true });
  }
  if (usesNode) out.push({ product: 'nodejs', kind: 'Installed on this machine (node)', version: process.versions.node, file: '(local)', pinned: true, local: true });
  return out;
}

// ───────────────────────────── network ─────────────────────────────

const CACHE_DIR = path.join(os.tmpdir(), 'vuln-guard-cache');
let networkFailures = 0;

const DEAD_HOSTS = new Map(); // host → reason; fail fast after the first connection failure

async function http(url, opts = {}, timeoutMs = 25000) {
  const host = new URL(url).host;
  if (DEAD_HOSTS.has(host)) throw new Error(`${host}: ${DEAD_HOSTS.get(host)} (skipped)`);
  let r;
  try {
    r = await fetch(url, { ...opts, signal: AbortSignal.timeout(timeoutMs), headers: { 'user-agent': `vuln-guard/${TOOL_VERSION}`, ...(opts.headers || {}) } });
  } catch (e) {
    networkFailures++;
    const reason = e.cause?.code || (e.name === 'TimeoutError' ? 'timeout' : e.message);
    DEAD_HOSTS.set(host, reason);
    throw new Error(`${host}: ${reason}`);
  }
  if (!r.ok) { networkFailures++; throw new Error(`${host}: HTTP ${r.status}`); }
  return await r.json();
}

async function cachedJson(name, url, ttlHours) {
  const f = path.join(CACHE_DIR, name);
  try {
    const st = fs.statSync(f);
    if (Date.now() - st.mtimeMs < ttlHours * 3600e3) return JSON.parse(fs.readFileSync(f, 'utf8'));
  } catch { /* miss */ }
  const j = await http(url);
  try { fs.mkdirSync(CACHE_DIR, { recursive: true }); fs.writeFileSync(f, JSON.stringify(j)); } catch { /* ignore */ }
  return j;
}

const OSV = 'https://api.osv.dev/v1';

async function osvQuery(pkgs) {
  const results = new Map(); // pkg key → [vuln ids]
  const batches = [];
  for (let i = 0; i < pkgs.length; i += 500) batches.push(pkgs.slice(i, i + 500));
  for (const batch of batches) {
    let queries = batch.map((p) => ({ package: { name: p.name, ecosystem: p.eco }, version: p.version }));
    let owners = batch;
    while (queries.length) {
      const j = await http(`${OSV}/querybatch`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ queries }) }, 60000);
      const nextQ = [], nextO = [];
      (j.results || []).forEach((r, i) => {
        const k = owners[i].key;
        if (!results.has(k)) results.set(k, []);
        for (const v of r.vulns || []) results.get(k).push(v.id);
        if (r.next_page_token) { nextQ.push({ ...queries[i], page_token: r.next_page_token }); nextO.push(owners[i]); }
      });
      queries = nextQ; owners = nextO;
    }
  }
  return results;
}

const VULN_CACHE = new Map();
async function osvVuln(id, quiet = false) {
  if (VULN_CACHE.has(id)) return VULN_CACHE.get(id);
  const p = http(`${OSV}/vulns/${encodeURIComponent(id)}`).catch((e) => { if (!quiet) note('warn', `OSV details for ${id} unavailable (${e.message})`); return null; });
  VULN_CACHE.set(id, p);
  return p;
}

async function loadKev() {
  const sources = [
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json',
  ];
  for (const [i, url] of sources.entries()) {
    try {
      const j = await cachedJson(`kev-${i}.json`, url, 12);
      const m = new Map();
      for (const v of j.vulnerabilities || []) m.set(v.cveID, { dateAdded: v.dateAdded, dueDate: v.dueDate, ransomware: v.knownRansomwareCampaignUse === 'Known', name: v.vulnerabilityName });
      return { map: m, catalogVersion: j.catalogVersion, source: new URL(url).host };
    } catch (e) { note('warn', `CISA KEV via ${new URL(url).host} failed (${e.message})`); }
  }
  return null;
}

async function loadEpss(cves) {
  const m = new Map();
  for (let i = 0; i < cves.length; i += 80) {
    const chunk = cves.slice(i, i + 80);
    try {
      const j = await http(`https://api.first.org/data/v1/epss?cve=${chunk.join(',')}`);
      for (const d of j.data || []) m.set(d.cve, { epss: Number(d.epss), percentile: Number(d.percentile) });
    } catch (e) { note('warn', `EPSS lookup failed (${e.message})`); break; }
  }
  return m;
}

const EOL_FAILED = [];
async function eolData(product) {
  try { return await cachedJson(`eol-${product}.json`, `https://endoflife.date/api/${product}.json`, 24); }
  catch (e) { EOL_FAILED.push(`${product} (${e.message.replace(/^endoflife\.date: /, '').replace(' (skipped)', '')})`); return null; }
}

// ───────────────────────────── severity ─────────────────────────────

function cvss3Score(vector) {
  const m = Object.fromEntries(vector.split('/').slice(1).map((p) => p.split(':')));
  const W = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }, AC: { L: 0.77, H: 0.44 }, UI: { N: 0.85, R: 0.62 },
    CIA: { H: 0.56, L: 0.22, N: 0 },
  };
  const changed = m.S === 'C';
  const PR = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR];
  const [av, ac, ui] = [W.AV[m.AV], W.AC[m.AC], W.UI[m.UI]];
  const [c, i, a] = [W.CIA[m.C], W.CIA[m.I], W.CIA[m.A]];
  if ([av, ac, ui, PR, c, i, a].some((x) => x === undefined)) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const expl = 8.22 * av * ac * PR * ui;
  if (impact <= 0) return 0;
  const roundup = (x) => { const n = Math.round(x * 100000); return n % 10000 === 0 ? n / 100000 : (Math.floor(n / 10000) + 1) / 10; };
  return roundup(Math.min(changed ? 1.08 * (impact + expl) : impact + expl, 10));
}

const SEV_RANK = { critical: 4, high: 3, moderate: 2, low: 1, unknown: 0 };
const labelFromScore = (s) => (s == null ? 'unknown' : s >= 9 ? 'critical' : s >= 7 ? 'high' : s >= 4 ? 'moderate' : s > 0 ? 'low' : 'unknown');
const normLabel = (l) => {
  l = String(l || '').toLowerCase();
  if (l === 'medium') return 'moderate';
  return SEV_RANK[l] !== undefined ? l : 'unknown';
};

function severityOf(v) {
  let score = null, label = 'unknown', vector = null;
  for (const s of v.severity || []) {
    if (s.type === 'CVSS_V3' && s.score) { vector = s.score; score = cvss3Score(s.score); }
    if (s.type === 'CVSS_V4' && !vector) vector = s.score;
  }
  const dbs = v.database_specific?.severity;
  if (dbs) label = normLabel(dbs);
  if (label === 'unknown') label = labelFromScore(score);
  if (label === 'unknown') {
    for (const a of v.affected || []) { const s = a.ecosystem_specific?.severity || a.database_specific?.severity; if (s) { label = normLabel(s); break; } }
  }
  return { label, score, vector };
}

// ───────────────────────────── matching ─────────────────────────────

function fixedVersionFor(v, pkg) {
  const fixes = [];
  let anyRange = false;
  for (const a of v.affected || []) {
    if (!a.package || a.package.ecosystem.split(':')[0] !== pkg.eco) continue;
    if (nameKey(pkg.eco, a.package.name) !== nameKey(pkg.eco, pkg.name)) continue;
    for (const r of a.ranges || []) {
      if (r.type === 'GIT') continue;
      anyRange = true;
      for (const e of r.events || []) if (e.fixed) fixes.push(e.fixed);
    }
  }
  const above = fixes.filter((f) => cmpVer(f, pkg.version) > 0).sort(cmpVer);
  return { fixed: above[0] || null, anyRange };
}

// ───────────────────────────── native tools ─────────────────────────────

function nativeNpmAudit() {
  const out = [];
  if (!which('npm')) return out;
  const dirs = new Set([...PKGS.values()].flatMap((p) => p.sources.filter((s) => s.manager === 'npm').map((s) => s.dir)));
  for (const dir of dirs) {
    if (!fs.existsSync(path.join(dir, 'package-lock.json'))) continue;
    const r = run('npm', ['audit', '--json', '--package-lock-only'], dir);
    const start = r.stdout.indexOf('{');
    if (start < 0) { note('warn', `npm audit in ${rel(dir)} produced no JSON (${(r.stderr || r.error?.message || '').split('\n')[0]})`); continue; }
    let j; try { j = JSON.parse(r.stdout.slice(start)); } catch { note('warn', `npm audit JSON unreadable in ${rel(dir)}`); continue; }
    if (j.error) { note('warn', `npm audit in ${rel(dir)}: ${j.error.summary || j.error.code}`); continue; }
    for (const [name, v] of Object.entries(j.vulnerabilities || {})) {
      for (const via of v.via || []) {
        if (typeof via !== 'object') continue;
        const ghsa = (String(via.url || '').match(/GHSA-[\w-]+/) || [])[0];
        out.push({ tool: 'npm audit', eco: ECO.npm, name: via.name || name, id: ghsa || String(via.source), title: via.title, severity: normLabel(via.severity), range: via.range, dir });
      }
    }
  }
  return out;
}

function nativeDotnet() {
  const out = [];
  if (!which('dotnet')) return out;
  const targets = [];
  walk(OPTS.path, 0, CFG, (file, base) => { if (/\.slnx?$/i.test(base)) targets.push(file); });
  if (!targets.length) walk(OPTS.path, 0, CFG, (file, base) => { if (/\.(cs|fs|vb)proj$/i.test(base)) targets.push(file); });
  for (const t of targets.slice(0, 20)) {
    const r = run('dotnet', ['list', t, 'package', '--vulnerable', '--include-transitive', '--format', 'json'], path.dirname(t), 300000);
    const start = r.stdout.indexOf('{');
    if (start < 0) { note('warn', `dotnet list package failed for ${rel(t)} (${(r.stderr || r.stdout || r.error?.message || '').trim().split('\n')[0]})`); continue; }
    let j; try { j = JSON.parse(r.stdout.slice(start)); } catch { note('warn', `dotnet list package JSON unreadable for ${rel(t)}`); continue; }
    for (const pr of j.problems || []) note('warn', `dotnet: ${pr.text || pr.message || JSON.stringify(pr)}`);
    for (const proj of j.projects || []) {
      for (const fw of proj.frameworks || []) {
        for (const [list, direct] of [[fw.topLevelPackages, true], [fw.transitivePackages, false]]) {
          for (const p of list || []) {
            for (const v of p.vulnerabilities || []) {
              const ghsa = (String(v.advisoryurl || '').match(/GHSA-[\w-]+/) || [])[0];
              out.push({ tool: 'dotnet list package', eco: ECO.nuget, name: p.id, version: p.resolvedVersion, id: ghsa || v.advisoryurl, severity: normLabel(v.severity), direct, project: proj.path ? rel(proj.path) : rel(t) });
            }
          }
        }
      }
    }
  }
  return out;
}

// ───────────────────────────── fix suggestions ─────────────────────────────

function fixCommand(p, fixed) {
  const src = p.sources[0] || {};
  const m = src.manager;
  const n = p.name, f = fixed;
  const dev = p.devOnly;
  if (!f) return null;
  switch (m) {
    case 'npm': return p.direct ? `npm install ${n}@${f}${dev ? ' --save-dev' : ''}` : `npm update ${n}  # if still vulnerable: add "overrides": { "${n}": "${f}" } to package.json, then npm install`;
    case 'pnpm': return p.direct ? `pnpm add ${n}@${f}${dev ? ' -D' : ''}` : `pnpm update ${n} --depth Infinity  # or pnpm.overrides: { "${n}": "${f}" }`;
    case 'yarn': return p.direct ? `yarn add ${n}@${f}${dev ? ' --dev' : ''}` : `yarn upgrade ${n}  # or "resolutions": { "${n}": "${f}" }`;
    case 'yarn-berry': return p.direct ? `yarn up ${n}@${f}` : `yarn up -R ${n}  # or "resolutions": { "${n}": "${f}" }`;
    case 'nuget-central': return p.direct
      ? `Directory.Packages.props: <PackageVersion Include="${n}" Version="${f}" />`
      : `Directory.Packages.props: add <PackageVersion Include="${n}" Version="${f}" /> and set <CentralPackageTransitivePinningEnabled>true</CentralPackageTransitivePinningEnabled> (or add <PackageReference Include="${n}" /> to ${src.project || 'the project'})`;
    case 'nuget': return `dotnet add "${src.project || '<project>.csproj'}" package ${n} --version ${f}${p.direct ? '' : '  # pins the transitive package explicitly'}`;
    case 'nuget-packages-config': return `Update-Package ${n} -Version ${f}  # packages.config (Visual Studio Package Manager Console)`;
    case 'pip': return `${src.file}: ${n}==${f}`;
    case 'poetry': return `poetry add "${n}>=${f}"  # or poetry update ${n}`;
    case 'uv': return `uv lock --upgrade-package ${n}`;
    case 'pipenv': return `pipenv update ${n}`;
    case 'bun': return p.direct ? `bun add ${n}@${f}${dev ? ' -d' : ''}` : `bun update ${n}  # or "overrides": { "${n}": "${f}" } in package.json`;
    case 'go': return `go get ${n}@v${f} && go mod tidy`;
    case 'go-toolchain': return `go get toolchain@go${f}  # and build / deploy with Go ${f} or newer`;
    case 'cargo': return `cargo update -p ${n} --precise ${f}`;
    case 'bundler': return `bundle update ${n} --conservative`;
    case 'composer': return `composer update ${n} --with-dependencies`;
    case 'maven': return `pom.xml: set ${n} to ${f} (or in <dependencyManagement>)`;
    case 'gradle': return `build.gradle: constraints { implementation("${n}:${f}") }  then gradle dependencies --write-locks`;
    case 'pub': return `dart pub upgrade ${n}`;
    default: return `upgrade ${n} to ${f}`;
  }
}

// ───────────────────────────── main ─────────────────────────────

const OPTS = parseArgs(process.argv.slice(2));
const CFG = loadConfig();

async function main() {
  const started = new Date();
  collect(CFG);

  let pkgs = [...PKGS.values()].map((p) => ({ ...p, key: `${p.eco}|${nameKey(p.eco, p.name)}|${p.version}` }));
  if (!OPTS.dev) pkgs = pkgs.filter((p) => !p.devOnly);
  const privatePkgs = pkgs.filter((p) => CFG.private.some((re) => re.test(p.name)));
  const queryPkgs = pkgs.filter((p) => !privatePkgs.includes(p));
  if (privatePkgs.length) note('info', `${privatePkgs.length} private/internal package(s) matched config.private and were not sent to OSV.`);

  // ── advisory lookups ──
  const findings = new Map(); // pkgKey|vulnId → finding
  let osvOk = false;
  if (!OPTS.offline && queryPkgs.length) {
    try {
      const hits = await osvQuery(queryPkgs);
      osvOk = true;
      const ids = [...new Set([...hits.values()].flat())];
      await mapLimit(ids, 8, osvVuln);
      for (const p of queryPkgs) {
        for (const id of hits.get(p.key) || []) {
          const v = await osvVuln(id);
          addFinding(findings, p, id, v, 'OSV');
        }
      }
    } catch (e) {
      note('error', `OSV.dev unreachable (${e.message}). Falling back to local tools only. ${proxyHint()}`);
    }
  } else if (OPTS.offline) note('info', 'Offline mode: OSV, KEV, EPSS and EOL lookups skipped.');

  // ── native tools ──
  const toolsRun = [];
  if (OPTS.native) {
    const natives = [...nativeNpmAudit(), ...nativeDotnet()];
    for (const t of new Set(natives.map((n) => n.tool))) toolsRun.push(t);
    for (const n of natives) {
      const p = findPkgForNative(pkgs, n);
      if (!p) continue;
      const nk = nameKey(n.eco, n.name);
      const existing = [...findings.values()].find((f) => f.pkg.eco === n.eco && nameKey(f.pkg.eco, f.pkg.name) === nk && f.ids.includes(n.id) && (!n.version || f.pkg.version === n.version));
      if (existing) { if (!existing.foundBy.includes(n.tool)) existing.foundBy.push(n.tool); continue; }
      const v = !OPTS.offline && osvOk && /^GHSA-/.test(n.id) ? await osvVuln(n.id) : null;
      const f = addFinding(findings, p, n.id, v, n.tool);
      if (f && !v) {
        f.summary = n.title || f.summary;
        if (f.severity.label === 'unknown') f.severity.label = n.severity;
        // npm audit ranges like "<3.0.5" or ">=2.0.0 <2.3.1" give the fix directly
        const up = String(n.range || '').match(/<\s*([0-9][\w.-]*)\s*$/);
        if (up && cmpVer(up[1], p.version) > 0) f.fixed = up[1];
      }
    }
  }

  // ── missing severity ──
  // Go (GO-…) and some PyPI (PYSEC-…) records carry no score; the GHSA or Bitnami (BIT-…) record for the same CVE usually does.
  if (!OPTS.offline && osvOk) {
    const unrated = [...findings.values()].filter((f) => f.severity.label === 'unknown');
    const alias = (f) => ['GHSA-', 'BIT-', 'CVE-'].map((pre) => f.ids.find((x) => x.startsWith(pre) && x !== f.ids[0])).find(Boolean);
    await mapLimit([...new Set(unrated.map(alias).filter(Boolean))], 8, (id) => osvVuln(id, true));
    for (const f of unrated) {
      const id = alias(f); if (!id) continue;
      const v = await osvVuln(id, true);
      if (v) { const s = severityOf(v); if (s.label !== 'unknown') f.severity = { ...s, from: id }; }
    }
  }

  // ── ignore list ──
  const now = new Date();
  const ignored = [];
  for (const [k, f] of findings) {
    const rule = CFG.ignore.find((r) => r.id && f.ids.includes(r.id) && (!r.package || nameKey(f.pkg.eco, r.package) === nameKey(f.pkg.eco, f.pkg.name)));
    if (!rule) continue;
    if (rule.expires && new Date(rule.expires) < now) { note('warn', `Ignore rule for ${rule.id} expired on ${rule.expires} — reported again.`); continue; }
    ignored.push({ id: f.displayId, package: f.pkg.name, reason: rule.reason || '(no reason given)', expires: rule.expires || null });
    findings.delete(k);
  }

  // ── KEV / EPSS ──
  let kev = null;
  const list = [...findings.values()];
  const cves = [...new Set(list.flatMap((f) => f.cves))];
  if (!OPTS.offline && cves.length) {
    kev = await loadKev();
    const epss = OPTS.epss ? await loadEpss(cves) : new Map();
    for (const f of list) {
      for (const c of f.cves) {
        const k = kev?.map.get(c); if (k) f.kev = { cve: c, ...k };
        const e = epss.get(c); if (e && (!f.epss || e.epss > f.epss.epss)) f.epss = { cve: c, ...e };
      }
    }
  }

  // ── priority ──
  for (const f of list) {
    const s = SEV_RANK[f.severity.label];
    let pr = f.kev ? 0 : s >= 4 || (s >= 3 && (f.epss?.epss ?? 0) >= 0.1) ? 1 : s === 3 ? 2 : s === 2 ? 3 : 4;
    if (f.pkg.devOnly && pr > 0) pr = Math.min(pr + 1, 4);
    f.priority = pr;
  }
  list.sort((a, b) => a.priority - b.priority || SEV_RANK[b.severity.label] - SEV_RANK[a.severity.label] || (b.epss?.epss ?? 0) - (a.epss?.epss ?? 0) || a.pkg.name.localeCompare(b.pkg.name));

  // ── runtimes ──
  let runtimes = [];
  if (OPTS.runtime) runtimes = await checkRuntimes();

  // ── fix plan ──
  const plan = buildPlan(list);

  // A result is only "verified" if at least one advisory source actually answered.
  const verified = osvOk || toolsRun.length > 0 || pkgs.length === 0;
  if (!verified) note('error', 'NOT VERIFIED: no advisory source (OSV, npm audit, dotnet) could be used, so "0 vulnerabilities" means "not checked". Fix network access or run with the native tools available.');
  else if (!osvOk && toolsRun.length) note('warn', `Partial coverage: only ${toolsRun.join(' + ')} results — other ecosystems (${Object.keys(groupCount(pkgs, (p) => p.eco)).filter((e) => !(e === 'npm' && toolsRun.includes('npm audit')) && !(e === 'NuGet' && toolsRun.includes('dotnet list package'))).join(', ') || 'none'}) were not checked.`);

  const report = {
    tool: { name: 'vuln-guard', version: TOOL_VERSION },
    scannedAt: started.toISOString(),
    path: OPTS.path,
    verified,
    sources: {
      osv: OPTS.offline ? 'skipped (offline)' : osvOk ? 'ok' : 'failed',
      kev: kev ? `ok (${kev.source}, catalog ${kev.catalogVersion})` : OPTS.offline || !cves.length ? 'skipped' : 'failed',
      nativeTools: toolsRun,
    },
    inventory: {
      packages: pkgs.length,
      byEcosystem: Object.fromEntries(Object.entries(groupCount(pkgs, (p) => p.eco))),
      files: [...new Set(FILES_SEEN)].sort(),
      unpinned: UNPINNED.slice(0, 50),
      privateSkipped: privatePkgs.map((p) => `${p.name}@${p.version}`),
    },
    summary: summarise(list, runtimes),
    runtimes,
    findings: list.map(serialiseFinding),
    fixPlan: plan,
    ignored,
    notes,
  };

  fs.mkdirSync(OPTS.out, { recursive: true });
  const md = renderMarkdown(report);
  fs.writeFileSync(path.join(OPTS.out, 'report.json'), JSON.stringify(report, null, 2));
  fs.writeFileSync(path.join(OPTS.out, 'report.md'), md);
  if (OPTS.sarif) { fs.mkdirSync(path.dirname(OPTS.sarif), { recursive: true }); fs.writeFileSync(OPTS.sarif, JSON.stringify(renderSarif(report), null, 2)); }

  if (OPTS.json) process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  else if (OPTS.quiet) process.stdout.write(summaryLine(report) + '\n');
  else process.stdout.write(md + '\n');
  process.stderr.write(`\nReport written to ${path.join(OPTS.out, 'report.md')} (+ report.json)\n`);

  // exit codes: 0 ok · 1 findings at/above --fail-on · 2 tool error · 3 could not verify (only with --fail-on)
  process.exitCode = shouldFail(list) ? 1 : !verified && OPTS.failOn !== 'none' ? 3 : 0;
}

function proxyHint() {
  const proxy = process.env.HTTPS_PROXY || process.env.https_proxy;
  if (proxy && !process.env.NODE_USE_ENV_PROXY) return 'HTTPS_PROXY is set but Node ignores it — set NODE_USE_ENV_PROXY=1 (Node >= 22.21 / 24.5).';
  return 'If you are behind a corporate proxy, set HTTPS_PROXY and NODE_USE_ENV_PROXY=1; for TLS inspection set NODE_EXTRA_CA_CERTS.';
}

function findPkgForNative(pkgs, n) {
  const nk = nameKey(n.eco, n.name);
  const cands = pkgs.filter((p) => p.eco === n.eco && nameKey(p.eco, p.name) === nk);
  if (n.version) return cands.find((p) => p.version === n.version) || null;
  if (n.dir) return cands.find((p) => p.sources.some((s) => s.dir === n.dir)) || cands[0] || null;
  return cands[0] || null;
}

function addFinding(map, p, id, v, foundBy) {
  if (v?.withdrawn) return null;
  const ids = [...new Set([id, v?.id, ...(v?.aliases || [])].filter(Boolean))];
  const key = `${p.key}|${ids.find((x) => x.startsWith('GHSA-')) || ids[0]}`;
  // dedupe: an OSV id + its alias reported by another source
  for (const f of map.values()) if (f.pkg.key === p.key && f.ids.some((x) => ids.includes(x))) { if (!f.foundBy.includes(foundBy)) f.foundBy.push(foundBy); return f; }
  const { fixed, anyRange } = v ? fixedVersionFor(v, p) : { fixed: null, anyRange: false };
  const f = {
    pkg: p, ids,
    displayId: ids.find((x) => x.startsWith('CVE-')) || ids.find((x) => x.startsWith('GHSA-')) || ids[0],
    cves: ids.filter((x) => x.startsWith('CVE-')),
    summary: (v?.summary || (v?.details || '').split('\n')[0] || '').slice(0, 160),
    severity: v ? severityOf(v) : { label: 'unknown', score: null, vector: null },
    fixed, noFixYet: Boolean(v && anyRange && !fixed),
    published: v?.published || null,
    url: ids.find((x) => x.startsWith('GHSA-')) ? `https://github.com/advisories/${ids.find((x) => x.startsWith('GHSA-'))}` : `https://osv.dev/vulnerability/${ids[0]}`,
    foundBy: [foundBy], kev: null, epss: null, priority: 4,
  };
  map.set(key, f);
  return f;
}

function serialiseFinding(f) {
  return {
    priority: `P${f.priority}`,
    id: f.displayId, aliases: f.ids,
    ecosystem: f.pkg.eco, package: f.pkg.name, version: f.pkg.version,
    direct: f.pkg.direct, devOnly: f.pkg.devOnly,
    severity: f.severity.label, cvss: f.severity.score, vector: f.severity.vector,
    kev: f.kev, epss: f.epss,
    fixedIn: f.fixed, noFixYet: f.noFixYet,
    majorUpgrade: isMajorMove(f.pkg, f.fixed),
    summary: f.summary, url: f.url, published: f.published,
    files: f.pkg.sources.map((s) => s.file), project: f.pkg.sources.find((s) => s.project)?.project || null,
    manager: f.pkg.sources[0]?.manager, foundBy: f.foundBy,
  };
}

function buildPlan(list) {
  const byPkg = new Map();
  for (const f of list) {
    const k = f.pkg.key;
    if (!byPkg.has(k)) byPkg.set(k, { pkg: f.pkg, fs: [] });
    byPkg.get(k).fs.push(f);
  }
  const plan = [];
  for (const { pkg, fs: fl } of byPkg.values()) {
    const fixes = fl.map((f) => f.fixed).filter(Boolean).sort(cmpVer);
    const target = fixes[fixes.length - 1] || null; // must clear every advisory
    plan.push({
      priority: `P${Math.min(...fl.map((f) => f.priority))}`,
      ecosystem: pkg.eco, package: pkg.name, from: pkg.version, to: target,
      majorUpgrade: isMajorMove(pkg, target),
      direct: pkg.direct, devOnly: pkg.devOnly,
      fixes: fl.filter((f) => f.fixed).map((f) => f.displayId),
      noFixAvailable: fl.filter((f) => f.noFixYet).map((f) => f.displayId),
      fixUnknown: fl.filter((f) => !f.fixed && !f.noFixYet).map((f) => ({ id: f.displayId, url: f.url })),
      command: fixCommand(pkg, target),
      files: pkg.sources.map((s) => s.file),
    });
  }
  plan.sort((a, b) => a.priority.localeCompare(b.priority) || a.package.localeCompare(b.package));
  return plan;
}

async function checkRuntimes() {
  const decl = [...RUNTIMES, ...localRuntimes()];
  if (!decl.length) return [];
  const products = [...new Set(decl.map((r) => r.product))];
  const data = new Map();
  if (!OPTS.offline) {
    // one probe first so an unreachable host costs a single timeout, not one per product
    data.set(products[0], await eolData(products[0]));
    await mapLimit(products.slice(1), 4, async (p) => data.set(p, await eolData(p)));
    if (EOL_FAILED.length) note('warn', `endoflife.date lookups failed for ${EOL_FAILED.join(', ')} — runtime patch/EOL status unknown for those.`);
  }
  const today = new Date();
  return decl.map((r) => {
    const out = { product: r.product, where: r.kind, file: r.alsoIn ? `${r.file} (+${r.alsoIn} more)` : r.file, version: r.version, cycle: null, latest: null, eol: null, status: 'unknown', advice: null };
    if (r.floatingTag) { out.status = 'warn'; out.advice = `Floating tag "${r.floatingTag}" — pin a version (e.g. major.minor) so you know what is deployed.`; return out; }
    const rows = data.get(r.product);
    if (!rows || !Array.isArray(rows)) { out.status = OPTS.offline ? 'skipped' : 'unknown'; return out; }
    const v = r.version;
    const cyc = rows.filter((c) => v === String(c.cycle) || v.startsWith(String(c.cycle) + '.')).sort((a, b) => String(b.cycle).length - String(a.cycle).length)[0];
    if (!cyc) { out.status = 'unknown'; out.advice = 'Version cycle not found on endoflife.date'; return out; }
    out.cycle = String(cyc.cycle); out.latest = cyc.latest || null; out.eol = cyc.eol;
    const eolDate = typeof cyc.eol === 'string' ? new Date(cyc.eol) : null;
    const isEol = cyc.eol === true || (eolDate && eolDate <= today);
    const soon = eolDate && !isEol && (eolDate - today) / 86400e3 <= 120;
    const behind = r.pinned && out.latest && cmpVer(v, out.latest) < 0;
    const newest = rows.filter((c) => !(c.eol === true || (typeof c.eol === 'string' && new Date(c.eol) <= today))).map((c) => String(c.cycle)).sort(cmpVer).pop();
    if (r.sdk) {
      out.latest = null;
      out.status = isEol ? 'eol' : soon ? 'eol-soon' : 'ok';
      out.advice = `${isEol ? `End of life since ${cyc.eol}. ` : soon ? `Support ends ${cyc.eol} — plan the move to ${newest}. ` : ''}SDK pin only affects builds; the shipped runtime patch comes from your base image / server.`;
    }
    else if (r.minimum && isEol) { out.status = 'warn'; out.advice = `package.json still allows Node ${v} (EOL since ${cyc.eol}). Raise the minimum to a supported version (${newest}) and check what the servers actually run.`; }
    else if (isEol) { out.status = 'eol'; out.advice = `End of life since ${cyc.eol === true ? 'earlier' : cyc.eol} — no more security patches. Move to ${newest || 'a supported version'}.`; }
    else if (behind) { out.status = 'outdated'; out.advice = `Patch ${out.latest} is available (security fixes usually included).${soon ? ` Also: support ends ${cyc.eol}.` : ''}`; }
    else if (soon) { out.status = 'eol-soon'; out.advice = `Support ends ${cyc.eol} — plan the move to ${newest || 'a newer version'}.`; }
    else { out.status = 'ok'; if (!r.pinned) out.advice = r.product === 'dotnet' ? 'Major version only — make sure servers / images run the latest patch.' : 'Only major/minor declared — make sure the deployed patch is current.'; }
    return out;
  });
}

function groupCount(arr, fn) { const m = {}; for (const x of arr) { const k = fn(x); m[k] = (m[k] || 0) + 1; } return m; }

function summarise(list, runtimes) {
  return {
    findings: list.length,
    kev: list.filter((f) => f.kev).length,
    critical: list.filter((f) => f.severity.label === 'critical').length,
    high: list.filter((f) => f.severity.label === 'high').length,
    moderate: list.filter((f) => f.severity.label === 'moderate').length,
    low: list.filter((f) => f.severity.label === 'low').length,
    unknown: list.filter((f) => f.severity.label === 'unknown').length,
    noFixYet: list.filter((f) => f.noFixYet).length,
    fixUnknown: list.filter((f) => !f.fixed && !f.noFixYet).length,
    affectedPackages: new Set(list.map((f) => f.pkg.key)).size,
    runtimeIssues: runtimes.filter((r) => ['eol', 'outdated', 'eol-soon'].includes(r.status)).length,
  };
}

function summaryLine(r) {
  const s = r.summary;
  if (!r.verified) return `vuln-guard: NOT VERIFIED — ${r.inventory.packages} packages found but no advisory source was reachable (see notes in report.md) · ${s.runtimeIssues} runtime issue(s)`;
  return `vuln-guard: ${r.inventory.packages} packages scanned · ${s.findings} vulnerabilities in ${s.affectedPackages} packages (KEV ${s.kev}, critical ${s.critical}, high ${s.high}, moderate ${s.moderate}, low ${s.low}) · ${s.runtimeIssues} runtime issue(s)`;
}

function shouldFail(list) {
  const lvl = OPTS.failOn;
  if (lvl === 'none') return false;
  if (lvl === 'kev') return list.some((f) => f.kev);
  return list.some((f) => f.kev || SEV_RANK[f.severity.label] >= SEV_RANK[lvl]);
}

// ───────────────────────────── SARIF ─────────────────────────────

// GitHub code scanning reads properties["security-severity"] (0–10) to rank alerts
const SARIF_SCORE = { critical: 9.5, high: 8.0, moderate: 5.5, low: 2.0, unknown: 5.0 };
const SARIF_LEVEL = { critical: 'error', high: 'error', moderate: 'warning', low: 'note', unknown: 'warning' };

const LINES = new Map(); // file → lines, read once
function lineOf(file, name) {
  if (!LINES.has(file)) LINES.set(file, (readText(path.join(OPTS.path, file)) || '').split(/\r?\n/));
  const i = LINES.get(file).findIndex((l) => l.includes(name));
  return i >= 0 ? i + 1 : 1;
}

function renderSarif(r) {
  const rules = new Map();
  const results = [];
  for (const f of r.findings) {
    if (!rules.has(f.id)) {
      rules.set(f.id, {
        id: f.id,
        shortDescription: { text: f.summary || f.id },
        helpUri: f.url,
        help: { text: `${f.summary || f.id}\n${f.url}` },
        properties: { tags: ['security', 'dependency', f.ecosystem], 'security-severity': String(f.cvss ?? SARIF_SCORE[f.severity] ?? 5) },
      });
    }
    const fix = f.fixedIn ? `Upgrade to ${f.fixedIn}${f.majorUpgrade ? ' (major version — check breaking changes)' : ''}.` : f.noFixYet ? 'No fixed version released yet.' : 'See the advisory for the fixed version.';
    const exploited = f.kev ? ' ACTIVELY EXPLOITED (CISA KEV).' : '';
    const file = f.files[0] || '.';
    results.push({
      ruleId: f.id,
      level: f.kev ? 'error' : SARIF_LEVEL[f.severity] || 'warning',
      message: { text: `${f.package} ${f.version} (${f.ecosystem}, ${f.direct ? 'direct' : 'transitive'}${f.devOnly ? ', dev' : ''}): ${f.summary || f.id}.${exploited} ${fix}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: file, uriBaseId: '%SRCROOT%' }, region: { startLine: lineOf(file, f.package) } } }],
      partialFingerprints: { 'vulnGuard/v1': `${f.ecosystem}|${f.package}|${f.version}|${f.id}` },
      properties: { priority: f.priority },
    });
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'vuln-guard', version: r.tool.version, informationUri: 'https://github.com/ngkaizheng/vuln-guard', rules: [...rules.values()] } },
      results,
    }],
  };
}

// ───────────────────────────── markdown ─────────────────────────────

const esc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
const SEV_ICON = { critical: '🔴 critical', high: '🟠 high', moderate: '🟡 moderate', low: '⚪ low', unknown: '❔ unknown' };
const RT_ICON = { eol: '🔴 EOL', outdated: '🟠 patch behind', 'eol-soon': '🟡 EOL soon', ok: '🟢 ok', warn: '🟡 check', unknown: '❔', skipped: '–' };

function renderMarkdown(r) {
  const L = [];
  const s = r.summary;
  L.push(`# Vulnerability report — ${path.basename(r.path)}`);
  L.push('');
  L.push(`_Scanned ${r.scannedAt.replace('T', ' ').slice(0, 16)} UTC · vuln-guard ${r.tool.version} · OSV: ${r.sources.osv} · KEV: ${r.sources.kev}${r.sources.nativeTools.length ? ' · ' + r.sources.nativeTools.join(', ') : ''}_`);
  L.push('');
  if (!r.verified) { L.push('> ❌ **NOT VERIFIED** — no advisory source could be reached, so the dependency list below was **not** checked for vulnerabilities. See Notes.'); L.push(''); }
  L.push(`**${r.inventory.packages}** packages scanned (${Object.entries(r.inventory.byEcosystem).map(([k, v]) => `${k} ${v}`).join(', ') || 'none found'}).`);
  L.push(`**${s.findings}** known vulnerabilities in **${s.affectedPackages}** packages — ⚠️ actively exploited (KEV) **${s.kev}**, critical **${s.critical}**, high **${s.high}**, moderate **${s.moderate}**, low **${s.low}**${s.unknown ? `, unrated ${s.unknown}` : ''}. No fix released yet: ${s.noFixYet}${s.fixUnknown ? ` · fix version unknown: ${s.fixUnknown}` : ''}. Runtime/base-image issues: **${s.runtimeIssues}**.`);
  L.push('');

  if (r.runtimes.length) {
    L.push('## Runtimes & base images');
    L.push('');
    L.push('| Status | Runtime | Version | Latest patch | EOL | Where | Advice |');
    L.push('|---|---|---|---|---|---|---|');
    const order = { eol: 0, outdated: 1, 'eol-soon': 2, warn: 3, unknown: 4, ok: 5, skipped: 6 };
    for (const x of [...r.runtimes].sort((a, b) => order[a.status] - order[b.status])) {
      L.push(`| ${RT_ICON[x.status] || x.status} | ${esc(x.product)} | ${esc(x.version ?? '—')} | ${esc(x.latest ?? '—')} | ${esc(x.eol === false || x.eol == null ? '—' : x.eol === true ? 'yes' : x.eol)} | ${esc(x.where)} · \`${esc(x.file)}\` | ${esc(x.advice ?? '')} |`);
    }
    L.push('');
  }

  L.push('## Vulnerable packages');
  L.push('');
  if (!r.findings.length) {
    L.push(r.verified ? '✅ No known vulnerabilities found in the scanned dependencies.' : '⚠️ No advisory source could be reached — this is **not** a clean result. See notes.');
  } else {
    L.push('| Pri | Package | Version | Vulnerability | Severity | Exploited? | EPSS | Fixed in | Dep | Summary |');
    L.push('|---|---|---|---|---|---|---|---|---|---|');
    for (const f of r.findings) {
      const exploited = f.kev ? `**YES** — CISA KEV ${f.kev.dateAdded}${f.kev.ransomware ? ', ransomware' : ''}` : '—';
      const epss = f.epss ? `${(f.epss.epss * 100).toFixed(1)}%` : '—';
      const fixed = f.fixedIn ? `${f.fixedIn}${f.majorUpgrade ? ' ⚠️major' : ''}` : f.noFixYet ? '❌ no fix yet' : '?';
      const dep = `${f.direct ? 'direct' : 'transitive'}${f.devOnly ? ', dev' : ''}`;
      L.push(`| ${f.priority} | ${esc(f.package)} (${f.ecosystem}) | ${esc(f.version)} | [${esc(f.id)}](${f.url}) | ${SEV_ICON[f.severity] || f.severity}${f.cvss != null ? ` ${f.cvss}` : ''} | ${exploited} | ${epss} | ${esc(fixed)} | ${dep} | ${esc(f.summary)} |`);
    }
  }
  L.push('');
  L.push('Priority: **P0** actively exploited (CISA KEV) → fix today · **P1** critical, or high with EPSS ≥ 10% · **P2** high · **P3** moderate · **P4** low/unrated. Dev-only packages are bumped down one level.');
  L.push('');

  if (r.fixPlan.length) {
    L.push('## Fix plan');
    L.push('');
    L.push('| Pri | Package | From → To | Fixes | Command / change |');
    L.push('|---|---|---|---|---|');
    for (const p of r.fixPlan) {
      const to = p.to ? `${p.from} → **${p.to}**${p.majorUpgrade ? ' ⚠️ major — check breaking changes' : ''}`
        : p.noFixAvailable.length ? `${p.from} → ❌ no fixed version` : `${p.from} → ? (see advisory)`;
      const fixes = [...p.fixes, ...p.noFixAvailable.map((x) => `${x} (no fix)`), ...p.fixUnknown.map((x) => `${x.id} (fix version unknown)`)].join(', ');
      const cmd = p.command ? '`' + esc(p.command) + '`'
        : p.noFixAvailable.length ? 'No patch yet: mitigate (config/WAF), replace the package, or watch the advisory'
        : `Check ${p.fixUnknown.map((x) => `[${x.id}](${x.url})`).join(', ')} for the patched version`;
      L.push(`| ${p.priority} | ${esc(p.package)} | ${esc(to)} | ${esc(fixes)} | ${cmd} |`);
    }
    L.push('');
  }

  if (r.ignored.length) {
    L.push('## Ignored by config');
    L.push('');
    for (const i of r.ignored) L.push(`- ${i.id} in ${i.package}: ${i.reason}${i.expires ? ` (until ${i.expires})` : ''}`);
    L.push('');
  }

  if (r.notes.length || r.inventory.unpinned.length) {
    L.push('## Notes');
    L.push('');
    for (const n of r.notes) L.push(`- ${n.level === 'error' ? '❌' : n.level === 'warn' ? '⚠️' : 'ℹ️'} ${n.msg}`);
    if (r.inventory.unpinned.length) L.push(`- ℹ️ ${r.inventory.unpinned.length} dependency spec(s) without an exact version were skipped (e.g. ${r.inventory.unpinned.slice(0, 3).map((u) => `${u.name} ${u.spec}`).join(', ')}).`);
    L.push('');
  }

  L.push('<details><summary>Files scanned</summary>');
  L.push('');
  for (const f of r.inventory.files) L.push(`- \`${f}\``);
  L.push('');
  L.push('</details>');
  return L.join('\n');
}

main().catch((e) => { process.stderr.write(`vuln-guard failed: ${e.stack || e}\n`); process.exit(2); });
