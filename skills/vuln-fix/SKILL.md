---
name: vuln-fix
description: Fix known vulnerabilities found by vuln-check — upgrades vulnerable dependencies (npm/pnpm/yarn/bun, NuGet, PyPI, Go, Cargo, Maven/Gradle, Composer, RubyGems, Pub) and outdated runtime/base-image patch versions on a local branch, then builds, tests and re-scans; major upgrades are listed for the user to decide. Never commits or pushes. Use when asked to fix, patch or remediate vulnerabilities/CVEs, upgrade vulnerable packages, resolve npm audit / Dependabot alerts, or "apply the vuln-check results".
---

# vuln-fix

Turn a vuln-check report into tested changes on a local branch. The user stays in control: **this skill never commits, pushes, opens PRs, or publishes anything.** It leaves uncommitted changes plus a PR description for the user to review.

Scan engine: [../vuln-check/scripts/scan.mjs](../vuln-check/scripts/scan.mjs) (or `.vuln-guard/scan.mjs` in the project). Per-ecosystem commands: [reference/fix-recipes.md](reference/fix-recipes.md).

## Rules

- Fix what the report says, nothing more. No drive-by upgrades of unrelated packages.
- Patch/minor upgrades that fix a vulnerability: apply after the user confirms the plan.
- **Major upgrades, runtime major moves (e.g. .NET 8 → 10, Node 18 → 22), and anything with no fixed version: do not apply.** Write them up with the breaking-change notes and let the user decide.
- Never: `npm audit fix --force`, delete a lockfile to regenerate it, bump versions in a lockfile by hand, add `ignore` entries to `.vuln-guard/config.json`, disable NuGet Audit, or edit vendored code.
- If build or tests fail because of an upgrade and the cause isn't obvious and small, revert that one package and mark it "needs manual work" — don't refactor the app to make an upgrade fit.

## Steps

### 1. Prepare
1. `git status`. If not a git repo → work in place but tell the user changes can't be reverted with git. If there are uncommitted changes → ask whether to continue on top of them or stop.
2. Create a local branch: `git switch -c security/vuln-fix-YYYYMMDD` (local only).
3. Make sure the graph is complete: `dotnet restore` for .NET; JS projects should already have a lockfile.

### 2. Scan and plan
1. Run `node <scan.mjs> --path . --quiet` and read `.vuln-guard/reports/report.json` → `fixPlan`, `findings`, `runtimes`, `notes`. If `verified` is false, stop and fix connectivity first (see vuln-check).
2. Sort the plan into three groups and show it to the user (their language), most urgent first:
   - **Will apply** — `to` is set and `majorUpgrade` is false. One line each: package, from → to, CVEs fixed, direct/transitive, file.
   - **Needs your decision** — major upgrades; runtime/base-image moves (`eol`, `eol-soon`); patch bumps of Docker base images that run in production.
   - **No fix available** — with a suggested mitigation (config, WAF, remove/replace package).
3. Ask once: apply the "will apply" group? (Options: all / only P0–P1 / let me pick.) Include base-image patch bumps (e.g. `aspnet:8.0.11` → `8.0.23`) if the user agrees.

### 3. Apply, one ecosystem at a time
For each ecosystem / project folder:
1. Apply the upgrades with the package manager's own command (see recipes) so lockfiles stay consistent. For transitive packages, first try updating the parent; if the fix still isn't pulled in, use the ecosystem's override/pinning mechanism.
2. Restore/install from the updated lockfile.
3. Build. Then run the existing tests (`dotnet test`, `npm test`/`pnpm test`, `pytest`, `go test ./...`, …). Don't invent new test suites; if there are no tests, say so.
4. On failure: read the error. If it is a small, obvious API change caused by the upgrade, fix it and mention it. Otherwise revert that package's change (`git checkout -- <files>` for the affected manifest/lockfile, reinstall) and move it to "needs manual work".

### 4. Re-scan and compare
Run the scan again. Report: fixed (before → after), still open and why, new findings (a new version can pull in something else — say so).

### 5. Hand over
1. Write `.vuln-guard/reports/PR_DESCRIPTION.md`: summary, table of upgrades with CVEs, build/test results, items needing decisions, items with no fix, how it was verified.
2. Tell the user: branch name, files changed (`git status --short`), what was verified, and the commands to finish when they're happy:
   ```
   git add -p
   git commit -m "fix(security): upgrade vulnerable dependencies"
   git push -u origin <branch>
   ```
   Do **not** run these yourself.

## Runtime and base-image changes

- **Patch bump in the same line** (e.g. `mcr.microsoft.com/dotnet/aspnet:8.0.11` → `8.0.23`, `node:22.11-alpine` → `node:22.22-alpine`): edit the Dockerfile tag if the user agreed. Note that the image must be rebuilt and redeployed to take effect.
- **Floating tags** (`aspnet:8.0`): no edit needed; tell the user to rebuild with `--pull` and redeploy.
- **Servers/IIS** running the runtime directly: can't be fixed from the repo — list the hosting bundle / runtime version to install.
- **Major move because of EOL** (.NET 8 → 10, Node 18 → 22, Python 3.8 → 3.12…): produce a checklist (TargetFramework/engines/image tags, SDK in global.json and CI, breaking changes to read, packages that need newer majors) — don't do the migration in this skill unless the user explicitly asks.
