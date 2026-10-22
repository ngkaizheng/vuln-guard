// node --test test/scan.test.mjs            offline checks (lockfile parsing, runtimes, exit codes)
// VG_ONLINE=1 node --test test/scan.test.mjs  also queries OSV.dev / CISA KEV for real
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const SCAN = path.join(here, '..', 'skills', 'vuln-check', 'scripts', 'scan.mjs');
const FIXTURE = path.join(here, 'fixtures', 'mixed');

function scan(...args) {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-test-'));
  const sarifFile = path.join(out, 'report.sarif');
  const r = spawnSync(process.execPath, [SCAN, '--path', FIXTURE, '--out', out, '--json', '--sarif', sarifFile, ...args], { encoding: 'utf8', timeout: 240000 });
  let report = null, sarif = null;
  try { report = JSON.parse(r.stdout); } catch { /* asserted by caller */ }
  try { sarif = JSON.parse(fs.readFileSync(sarifFile, 'utf8')); } catch { /* asserted by caller */ }
  fs.rmSync(out, { recursive: true, force: true });
  return { code: r.status, report, sarif, stderr: r.stderr };
}

const pkgs = (report, eco) => report.findings.filter((f) => f.ecosystem === eco);

const offline = scan('--offline', '--no-native');
test('offline scan produces a report', () => {
  assert.equal(offline.code, 0, offline.stderr);
  assert.ok(offline.report, 'stdout is JSON');
});

test('inventory counts every lockfile type', () => {
  const inv = offline.report.inventory;
  // npm: lodash, minimist 1.2.5 + nested 0.0.8 (package-lock v3), axios, follow-redirects, string-width + ansi-regex (npm alias), vite, esbuild, @babel/core (pnpm v9),
  // @babel/traverse (yarn v1),
  // express + nested body-parser + typescript (bun.lock; the workspace: entry is skipped, ", ]" inside a string survives),
  // left-pad from package.json because bunbad/bun.lock is broken
  assert.equal(inv.byEcosystem.npm, 15);
  // Go: golang.org/x/net, golang.org/x/text and the standard library from `toolchain go1.21.0`
  assert.equal(inv.byEcosystem.Go, 3);
  // Newtonsoft.Json via $(JsonVer) property, de-duplicated across two projects; System.Text.Encodings.Web
  assert.equal(inv.byEcosystem.NuGet, 2);
  // Django + requests[socks]; flask>=2.0 is unpinned
  assert.equal(inv.byEcosystem.PyPI, 2);
  assert.deepEqual(inv.unpinned.map((u) => u.name), ['flask']);
  for (const f of ['web/package-lock.json', 'pn/pnpm-lock.yaml', 'yarn/yarn.lock', 'py/requirements.txt', 'api/Api.csproj', 'api/Dockerfile', 'bun/bun.lock', 'go/go.mod']) {
    assert.ok(inv.files.includes(f), `scanned ${f}`);
  }
});

test('offline result is never reported as clean', () => {
  assert.equal(offline.report.verified, false);
  assert.ok(offline.report.notes.some((n) => /NOT VERIFIED/.test(n.msg)));
});

test('unreadable bun.lock falls back to package.json', () => {
  assert.ok(offline.report.notes.some((n) => /bunbad\/bun\.lock.*falling back/.test(n.msg)));
});

test('pnpm: transitive packages reachable only from devDependencies are dev-only', () => {
  const cfg = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-cfg-')), 'config.json');
  fs.writeFileSync(cfg, JSON.stringify({ private: ['*'] })); // lists every package in privateSkipped
  const prod = new Set(scan('--offline', '--no-native', '--no-runtime', '--no-dev', '--config', cfg).report.inventory.privateSkipped);
  fs.rmSync(path.dirname(cfg), { recursive: true, force: true });
  assert.ok(prod.has('axios@1.6.0') && prod.has('follow-redirects@1.15.0'), 'prod root and its dependency');
  assert.ok(prod.has('string-width@4.2.3') && prod.has('ansi-regex@5.0.0'), 'npm alias root and its dependency');
  for (const dev of ['vite@5.0.0', 'esbuild@0.19.0', '@babel/core@7.20.0']) assert.ok(!prod.has(dev), `${dev} is dev-only`);
});

test('missing restore is reported for .NET projects', () => {
  assert.ok(offline.report.notes.some((n) => /dotnet restore/.test(n.msg)));
});

test('runtimes: same TFM in two projects is one row; multi-stage alias skipped', () => {
  const rt = offline.report.runtimes.filter((r) => r.file !== '(local)');
  const tfm = rt.filter((r) => /TargetFramework net8\.0/.test(r.where));
  assert.equal(tfm.length, 1);
  assert.match(tfm[0].file, /\(\+1 more\)/);
  const images = rt.filter((r) => r.where.startsWith('Image '));
  assert.deepEqual(images.map((r) => r.where).sort(), ['Image mcr.microsoft.com/dotnet/aspnet:8.0.1', 'Image mcr.microsoft.com/dotnet/sdk:8.0']);
  assert.ok(rt.some((r) => r.product === 'python' && r.version === '3.12'));
  assert.ok(rt.some((r) => r.product === 'nodejs' && /engines/.test(r.where)));
});

test('SARIF is written even when there are no findings', () => {
  assert.equal(offline.sarif.version, '2.1.0');
  assert.equal(offline.sarif.runs[0].tool.driver.name, 'vuln-guard');
  assert.deepEqual(offline.sarif.runs[0].results, []);
});

test('--no-local leaves out runtimes installed on this machine', () => {
  const rt = scan('--offline', '--no-native', '--no-local').report.runtimes;
  assert.ok(rt.length > 0);
  assert.ok(rt.every((r) => r.file !== '(local)'));
});

test('--fail-on with no advisory source exits 3', () => {
  assert.equal(scan('--offline', '--no-native', '--no-runtime', '--fail-on', 'critical').code, 3);
});

test('bad option exits 2', () => {
  assert.equal(scan('--nope').code, 2);
});

test('online: known CVEs are found and ranked', { skip: !process.env.VG_ONLINE && 'set VG_ONLINE=1' }, () => {
  const { code, report, sarif } = scan('--no-native', '--fail-on', 'critical');
  assert.equal(report.verified, true);
  assert.equal(report.sources.osv, 'ok');
  const ids = (pkg) => report.findings.filter((f) => f.package === pkg).flatMap((f) => f.aliases);
  assert.ok(ids('lodash').includes('CVE-2021-23337'), 'lodash 4.17.20 command injection');
  assert.ok(ids('minimist').includes('CVE-2021-44906'), 'minimist prototype pollution');
  assert.ok(ids('Django').length > 5, 'Django 3.2.0 has many advisories');
  assert.ok(ids('Newtonsoft.Json').includes('CVE-2024-21907'), 'NuGet version resolved from $(JsonVer)');
  const lodash = report.findings.find((f) => f.aliases.includes('CVE-2021-23337'));
  assert.equal(lodash.fixedIn, '4.17.21');
  assert.equal(lodash.majorUpgrade, false);
  assert.equal(code, 1, 'critical findings fail the gate');

  // bun.lock: direct vs nested
  const express = report.findings.find((f) => f.package === 'express');
  assert.ok(express && express.direct && express.manager === 'bun');
  const bodyParser = report.findings.find((f) => f.package === 'body-parser');
  assert.ok(bodyParser && !bodyParser.direct, 'nested bun package is transitive');

  // Go: standard library CVEs, HTTP/2 Rapid Reset in KEV, severities borrowed from GHSA/Bitnami aliases
  const go = pkgs(report, 'Go');
  assert.ok(go.some((f) => f.package === 'stdlib' && f.aliases.includes('CVE-2023-39325')), 'stdlib 1.21.0');
  assert.ok(go.some((f) => f.kev && f.kev.cve === 'CVE-2023-44487' && f.priority === 'P0'), 'KEV → P0');
  assert.ok(go.filter((f) => f.severity === 'unknown').length < go.length / 10, 'most Go findings get a severity');
  const sameLine = go.find((f) => f.package === 'stdlib' && f.fixedIn?.startsWith('1.21.'));
  const newLine = go.find((f) => f.package === 'stdlib' && f.fixedIn && !f.fixedIn.startsWith('1.21.'));
  assert.ok(sameLine && newLine, 'stdlib has fixes in and after the 1.21 line');
  assert.equal(sameLine.majorUpgrade, false, 'Go 1.21.0 → 1.21.x is a patch');
  assert.equal(newLine.majorUpgrade, true, 'Go 1.21 → newer line needs a decision');

  // SARIF mirrors the findings; paths are relative to the git root (the fixture is inside this repo)
  const results = sarif.runs[0].results;
  assert.equal(results.filter((x) => !x.ruleId.startsWith('runtime-')).length, report.findings.length);
  const kevResult = results.find((x) => x.ruleId === 'CVE-2023-44487' && x.message.text.startsWith('golang.org/x/net'));
  assert.equal(kevResult.level, 'error');
  assert.equal(kevResult.locations[0].physicalLocation.artifactLocation.uri, 'test/fixtures/mixed/go/go.mod');
  assert.equal(kevResult.locations[0].physicalLocation.region.startLine, 8, 'line of golang.org/x/net in go.mod');
  // .NET 8 aspnet:8.0.1 image is behind on patches → a runtime result
  assert.ok(results.some((x) => x.ruleId.startsWith('runtime-') && /aspnet:8\.0\.1/.test(x.message.text)));
  for (const rule of sarif.runs[0].tool.driver.rules) assert.ok(Number(rule.properties['security-severity']) >= 0);
});
