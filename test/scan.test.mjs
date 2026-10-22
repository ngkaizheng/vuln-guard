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
const SCAN = path.join(here, '..', 'vuln-check', 'scripts', 'scan.mjs');
const FIXTURE = path.join(here, 'fixtures', 'mixed');

function scan(...args) {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-test-'));
  const r = spawnSync(process.execPath, [SCAN, '--path', FIXTURE, '--out', out, '--json', ...args], { encoding: 'utf8', timeout: 120000 });
  let report = null;
  try { report = JSON.parse(r.stdout); } catch { /* asserted by caller */ }
  fs.rmSync(out, { recursive: true, force: true });
  return { code: r.status, report, stderr: r.stderr };
}

const offline = scan('--offline', '--no-native');
test('offline scan produces a report', () => {
  assert.equal(offline.code, 0, offline.stderr);
  assert.ok(offline.report, 'stdout is JSON');
});

test('inventory counts every lockfile type', () => {
  const inv = offline.report.inventory;
  // npm: lodash, minimist 1.2.5 + nested 0.0.8 (package-lock v3), axios + @babel/core (pnpm v9), @babel/traverse (yarn v1)
  assert.equal(inv.byEcosystem.npm, 6);
  // Newtonsoft.Json via $(JsonVer) property, de-duplicated across two projects; System.Text.Encodings.Web
  assert.equal(inv.byEcosystem.NuGet, 2);
  // Django + requests[socks]; flask>=2.0 is unpinned
  assert.equal(inv.byEcosystem.PyPI, 2);
  assert.deepEqual(inv.unpinned.map((u) => u.name), ['flask']);
  for (const f of ['web/package-lock.json', 'pn/pnpm-lock.yaml', 'yarn/yarn.lock', 'py/requirements.txt', 'api/Api.csproj', 'api/Dockerfile']) {
    assert.ok(inv.files.includes(f), `scanned ${f}`);
  }
});

test('offline result is never reported as clean', () => {
  assert.equal(offline.report.verified, false);
  assert.ok(offline.report.notes.some((n) => /NOT VERIFIED/.test(n.msg)));
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

test('--fail-on with no advisory source exits 3', () => {
  assert.equal(scan('--offline', '--no-native', '--no-runtime', '--fail-on', 'critical').code, 3);
});

test('bad option exits 2', () => {
  assert.equal(scan('--nope').code, 2);
});

test('online: known CVEs are found and ranked', { skip: !process.env.VG_ONLINE && 'set VG_ONLINE=1' }, () => {
  const { code, report } = scan('--no-native', '--fail-on', 'critical');
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
});
