---
name: vuln-check
description: Scan the current project for published vulnerabilities that are still unfixed — dependencies in any ecosystem (npm/pnpm/yarn/bun, NuGet, PyPI, Maven/Gradle, Go incl. standard library, Cargo, RubyGems, Composer, Pub), runtimes (.NET, Node.js, Python, Go...) and Docker base images — and rank them by real-world risk, actively exploited (CISA KEV) first. Read-only. Use when asked to check for vulnerabilities, CVEs, GHSA or security advisories, to audit dependencies (like npm audit / dotnet list package --vulnerable but for every ecosystem at once), "are we affected by CVE-X" or by a newly announced vulnerability, whether a package or version is safe, outdated or end-of-life runtimes, or before a release.
---

# vuln-check

Find known, published vulnerabilities in this project that have not been fixed yet, rank them by real-world risk, and say exactly how to fix each one. This skill only **reads**: it never edits project files, installs packages, commits or pushes — the only thing it writes is the report in `.vuln-guard/reports/` (git-ignored after `vuln-setup`; otherwise tell the user it's there, or pass `--out` to put it elsewhere). (To apply fixes use the `vuln-fix` skill; to add CI scanning and hardening use `vuln-setup`.)

## What it checks

| Area | Source of truth |
|---|---|
| Dependencies in every lockfile/manifest it finds (see [ecosystems](reference/ecosystems.md)) | OSV.dev (aggregates GitHub Advisories, NVD, PyPA, RustSec, Go vulndb…) |
| Same, cross-checked with the package manager's own audit | `npm audit`, `pnpm audit`, `dotnet list package --vulnerable` (run automatically when installed) |
| Is it being exploited in the wild? | CISA Known Exploited Vulnerabilities (KEV) catalog |
| How likely is exploitation in the next 30 days? | FIRST EPSS |
| Runtime / SDK / base image patch level and end-of-life | endoflife.date (TargetFramework, global.json, Dockerfile `FROM`, compose `image:`, `.nvmrc`, `engines`, `.python-version`, `go.mod`, `.tool-versions`) |

Only package **names and versions** leave the machine — never source code. Internal packages can be excluded via `private` in `.vuln-guard/config.json`.

## Steps

1. **Find the scanner.** It is [scripts/scan.mjs](scripts/scan.mjs), next to this file. If you cannot locate the skill folder, use the project copy `.vuln-guard/scan.mjs` (created by `vuln-setup`). It needs Node.js 18+ and nothing else (no npm install, no PowerShell).
   - Check with `node --version`. If Node is missing or blocked, use the manual commands in [reference/manual-fallback.md](reference/manual-fallback.md) instead and build the same report by hand.

2. **Make the dependency graph complete (read-only preparation).**
   - .NET: if a project has `<PackageReference>` but no `obj/project.assets.json` and no `packages.lock.json`, run `dotnet restore` in the solution folder first — otherwise only direct packages are checked. Restore only writes to `obj/`.
   - npm/pnpm/yarn without a lockfile: do **not** run install (it changes files). Report it as a gap.
   - **Untrusted code** (a repo you just cloned from a stranger, a PR from a fork): skip `dotnet restore` and pass `--no-native`. `dotnet` evaluates MSBuild files, which can run code, and npm/pnpm read the repo's `.npmrc`. With `--no-native`, the scan only parses text and makes HTTPS lookups.

3. **Run the scan** from the project root:
   ```
   node <skill-dir>/scripts/scan.mjs --path . --quiet
   ```
   Then read `.vuln-guard/reports/report.json` (structured) or `report.md` (human-readable). Useful options: `--no-dev` (production deps only), `--offline` (no network), `--no-native` (skip npm audit / pnpm audit / dotnet), `--fail-on kev|critical|high` (CI gate), `--out <dir>`, `--sarif <file>` (only if the user wants results in GitHub code scanning). Run `--help` for all. Exit codes: 0 ok, 1 findings at/above `--fail-on`, 2 tool error, 3 could not verify. Scanning a large repo with the native tools can take a few minutes — `dotnet list package` is the slow part.

4. **Check the report is trustworthy before you summarise it.**
   - `"verified": false` or a "NOT VERIFIED" note means *nothing was actually checked* — never tell the user "no vulnerabilities". Fix connectivity first:
     - Corporate proxy: set `HTTPS_PROXY=http://host:port` **and** `NODE_USE_ENV_PROXY=1` (Node ≥ 22.21 / 24.5), then rerun.
     - TLS inspection errors (`UNABLE_TO_GET_ISSUER_CERT_LOCALLY`, `SELF_SIGNED_CERT_IN_CHAIN`): set `NODE_EXTRA_CA_CERTS=<company root CA .pem>`. Never disable TLS verification.
     - Still blocked: run with `--offline` (native tools still work through the company npm/NuGet mirror) and say clearly which ecosystems were not covered.
   - Read the `notes` array: missing lockfiles, restore needed, partial coverage. Mention the ones that affect the conclusion.

5. **Report to the user** (in the user's language), most important first:
   1. One-line verdict: counts by priority, and whether anything is **actively exploited** (KEV).
   2. A table of P0–P2 findings (all findings if there are fewer than ~15): package, current → fixed version, CVE/GHSA, severity, exploited?, direct/transitive, where (file/project).
   3. Runtime / base image issues — especially `eol` and `eol-soon` (e.g. a .NET or Node version whose support ends soon) and `outdated` patch levels.
   4. Anything with **no fix yet**: suggest a mitigation (config change, WAF rule, replacing the package, removing an unused dependency).
   5. Offer the next step: "run `vuln-fix` to apply the patch/minor upgrades".
   Keep the full table in the report file; don't paste hundreds of rows into chat.

## How to read priorities

- **P0** — in CISA KEV: attackers are using it now. Fix today, and if the component is internet-facing consider whether it was already exploited (check logs).
- **P1** — critical, or high with EPSS ≥ 10%.
- **P2** high · **P3** moderate · **P4** low/unrated. Dev-only dependencies are lowered one step (they don't ship to production, but they do run on developer machines and CI — still fix them).
- **⚠️ major** next to a fixed version = breaking-change upgrade; needs a person to review.
- **transitive** = pulled in by another package; fixing means updating the parent or pinning/overriding (see `vuln-fix`).
- A finding is about the *installed version*, not whether your code calls the vulnerable function. If the user asks "are we really exposed?", read the advisory (link in the table) and check whether the vulnerable feature is used — say what you checked and what you could not.

## "Are we affected by CVE-XXXX?"

1. Run the scan and search `report.json` (`findings[].aliases`) for the ID.
2. If not found: look up the CVE (web search / OSV) to learn the affected product and versions, then check the inventory (`report.json` → `inventory`, lockfiles, Dockerfiles) for that product.
3. If the CVE is about software this scanner does not see (OS packages, IIS, SQL Server, network appliances, browser), say so plainly and suggest the right check (e.g. `docker scout cves` / `trivy image` for container OS packages, Windows Update for the host).

## Limits — say these when relevant

- Known, published advisories only. Not a code scanner (SAST), not a secret scanner, not a pentest.
- Container images: base image *version/EOL* is checked, OS packages inside the image are not (use Trivy / Docker Scout / Grype).
- Maven `pom.xml`: direct dependencies only unless a `gradle.lockfile` or osv-scanner is used. Binary `bun.lockb` is not readable (ask for `bun install --save-text-lockfile`).
- Go standard library: checked only from the go.mod `toolchain` line, which may still differ from the Go that CI builds with. Without one, say stdlib was not checked and suggest `govulncheck ./...`.
- Advisory databases lag a few hours to days behind vendor bulletins.

## Configuration (`.vuln-guard/config.json`)

```json
{
  "private": ["MyCompany.*", "@mycompany/*"],
  "ignore": [
    { "id": "CVE-2024-12345", "package": "some-lib", "reason": "vulnerable API not used — reviewed by <name>", "expires": "2027-03-31" }
  ],
  "skipDirs": ["samples", "legacy-archive"]
}
```
Ignored findings still appear under "Ignored by config"; expired rules stop working automatically. Never add an ignore rule on your own — only when the user explicitly decides to accept a risk, and always with a reason and an expiry date.
