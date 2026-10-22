---
name: vuln-setup
description: One-time setup that makes a project continuously checked for known vulnerabilities — adds the vuln-guard scanner and config to the repo, a CI job (GitHub Actions, Azure Pipelines or GitLab) that fails on exploited/critical CVEs, Dependabot, NuGet Audit settings for .NET, npm/pnpm supply-chain hardening, lockfile gaps, and agent instructions. Use when asked to set up vulnerability scanning, dependency security, security CI, or to "prepare this repo" for vuln-check / vuln-fix.
---

# vuln-setup

Prepare a repository so vulnerabilities are caught automatically and the `vuln-check` / `vuln-fix` skills work for everyone on the team — including people without these skills and in CI.

This skill **writes files** in the repo but **never commits, pushes, or changes CI settings on the server**. The user reviews and commits.

The scan engine lives in the sibling skill: [../vuln-check/scripts/scan.mjs](../vuln-check/scripts/scan.mjs). Templates are in [templates/](templates/).

## Steps

### 1. Detect the stack (no network, no changes)

```
node <skills-dir>/vuln-check/scripts/scan.mjs --path . --offline --no-native --json --out .vuln-guard/reports
```
From the JSON use `inventory.byEcosystem`, `inventory.files`, `runtimes` and `notes`. Also look for:
- CI system: `.github/workflows/`, `azure-pipelines.yml` / `*.azure-pipelines.yml`, `.gitlab-ci.yml`, `Jenkinsfile`.
- Existing `Directory.Build.props`, `.npmrc`, `pnpm-workspace.yaml`, `.github/dependabot.yml`, `renovate.json`, `.github/copilot-instructions.md`, `CLAUDE.md`, `AGENTS.md`.
- Internal package prefixes (e.g. `MyCompany.*`, `@company/*`) — these should go in `private` so they are never sent to OSV.

### 2. Propose a checklist and confirm

Show the user a short list of the items below that apply to this repo, with one line each on what file changes. Ask which to apply (default: all that apply). If the user already said "do everything", skip the question. Ask separately for the internal package prefixes if you are not sure.

### 3. Apply the chosen items

**A. Scanner in the repo** (always recommended)
- Copy `scan.mjs` to `.vuln-guard/scan.mjs`.
- Create `.vuln-guard/config.json` from [templates/config.json](templates/config.json) with the confirmed `private` prefixes and an empty `ignore` list.
- Add `.vuln-guard/reports/` to `.gitignore`.

**B. Lockfile gaps** (from the scan `notes`)
- npm project without a lockfile → offer `npm install --package-lock-only` (writes only the lockfile). pnpm/yarn: the equivalent install. Ask before running.
- Python with only `>=` requirements → suggest pinning (`pip-compile`, `uv lock`, or `poetry lock`); don't change it unasked.
- Gradle without `gradle.lockfile` → suggest dependency locking.
- .NET: optional `RestorePackagesWithLockFile` (reproducible restores; CI must then use `dotnet restore --locked-mode`). Explain the trade-off; default off.

**C. .NET — NuGet Audit** (if any NuGet packages)
- Merge [templates/nuget-audit.props](templates/nuget-audit.props) into `Directory.Build.props` at the solution root (create it if missing; if it exists, add a new `<PropertyGroup>` — don't rewrite existing properties).
- Effect: every `dotnet restore`/`build` warns about vulnerable packages, including transitive ones; CI builds fail on high/critical (`NU1903`/`NU1904`), local builds keep working.
- Afterwards run `dotnet restore` once to make sure the file is valid.

**D. JavaScript supply-chain hardening** (if npm/pnpm/yarn)
- See [templates/js-hardening.md](templates/js-hardening.md). Add the lines that fit the package manager; explain `ignore-scripts` before enabling it, because some packages (esbuild, sharp, prisma, husky…) need install scripts.
- CI must install with `npm ci` / `pnpm install --frozen-lockfile` / `yarn install --immutable`.

**E. CI scan job**
- Pick the template for the detected CI system: [GitHub Actions](templates/github-actions.yml), [Azure Pipelines](templates/azure-pipelines.yml), [GitLab](templates/gitlab-ci.yml). None detected → ask which one they use.
- Adapt it: remove the .NET steps if there is no .NET, point `dotnet restore` at the right solution, use the Node version from `.nvmrc`/`engines` when present, keep the weekly schedule (new CVEs appear without any code change).
- Gate: default `--fail-on critical` (also fails on anything actively exploited). Mention `kev` (gentler) and `high` (stricter). Exit code 3 = the scan could not reach any advisory source — usually a proxy problem on self-hosted agents; the template shows the proxy variables.
- Self-hosted agents behind a proxy: set `HTTPS_PROXY`, `NODE_USE_ENV_PROXY=1`, and `NODE_EXTRA_CA_CERTS` if TLS is inspected.

**F. Automated update PRs**
- GitHub: [templates/dependabot.yml](templates/dependabot.yml) — one entry per ecosystem and directory found (nuget, npm, pip, gomod, cargo, bundler, composer, maven/gradle, pub, docker, github-actions). Remind the user to also switch on *Dependabot security updates* in the repo settings (that part can't be done from a file).
- Azure DevOps / GitLab: suggest Renovate (a `renovate.json` with `"extends": ["config:recommended"]` and `"vulnerabilityAlerts": { "enabled": true }`), which needs a bot/pipeline set up by whoever owns the DevOps org. Don't pretend it works without that.

**G. Agent instructions**
- Append [templates/agent-instructions.md](templates/agent-instructions.md) to the instruction files that already exist (`.github/copilot-instructions.md`, `CLAUDE.md`, `AGENTS.md`). If none exist, ask before creating `.github/copilot-instructions.md`.

### 4. Verify

- Run `node .vuln-guard/scan.mjs --quiet` (online) and confirm it prints a verified summary. If it says NOT VERIFIED, fix the network settings first (see the `vuln-check` skill).
- If `Directory.Build.props` changed: `dotnet restore` succeeds.
- Re-read every YAML you wrote for indentation mistakes.

### 5. Hand over

Give a table: file → created/changed → why. Then: "Review with `git diff`, commit when happy. Run `vuln-check` any time; CI will also run it on every PR and weekly." Do not commit.

## Updating later

Re-running this skill is safe: it updates `.vuln-guard/scan.mjs` to the skill's version and only adds missing pieces. Never overwrite the user's `config.json` ignore list.
