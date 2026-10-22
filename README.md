# vuln-guard — vulnerability skills for Claude and GitHub Copilot

Three agent skills that find and fix **published, still-unfixed vulnerabilities** in any project:

| Skill | What it does | Changes files? |
|---|---|---|
| **vuln-check** | Scans dependencies (npm/pnpm/yarn, NuGet, PyPI, Maven/Gradle, Go, Cargo, RubyGems, Composer, Pub), runtimes (.NET, Node, Python, Go…) and Docker base images. Ranks by real risk: actively exploited (CISA KEV) first, then severity and EPSS. | No (report only) |
| **vuln-fix** | Applies the safe upgrades on a local branch, builds, tests, re-scans, writes a PR description. Majors and runtime moves are proposed, not applied. | Yes, uncommitted — **never commits or pushes** |
| **vuln-setup** | One-time per repo: scanner + config in the repo, CI job (GitHub Actions / Azure Pipelines / GitLab), Dependabot, NuGet Audit, npm/pnpm hardening, agent instructions. | Yes, uncommitted |

The same `SKILL.md` files work in **Claude Code**, **Claude (desktop/web)**, and **GitHub Copilot in VS Code** (agent mode). The scanning logic is one Node.js script with no dependencies, so it also runs on its own and in CI.

## Requirements

- Node.js 18 or newer (22.21+ / 24.5+ if you need to go through a corporate proxy). No `npm install`, no PowerShell.
- Optional, used automatically when present: `dotnet` SDK, `npm`.

## Install

With the [skills CLI](https://github.com/vercel-labs/skills) (Claude Code, Copilot, Codex, Cursor and others):

```bash
npx skills add ngkaizheng/vuln-guard          # this project
npx skills add ngkaizheng/vuln-guard -g       # all your projects
```

Or clone and use the bundled installer:

```bash
git clone https://github.com/ngkaizheng/vuln-guard && cd vuln-guard
# personal — Claude Code and VS Code Copilot both read ~/.claude/skills
node install.mjs
node install.mjs --copilot            # also ~/.copilot/skills

# for the whole team — commit the folder it creates
node install.mjs --project path/to/repo            # → repo/.claude/skills
node install.mjs --project path/to/repo --github   # → repo/.github/skills (Copilot cloud agent)
```
Or copy the three folders by hand into any skills folder. Keep them side by side: `vuln-setup` and `vuln-fix` use the scanner inside `vuln-check`.

VS Code: skills are picked up from `.github/skills`, `.claude/skills`, `.agents/skills` in the repo and `~/.copilot/skills`, `~/.claude/skills`, `~/.agents/skills` for you. Use Copilot Chat in **Agent** mode.

## Use

Just ask:
- "check this project for vulnerabilities" / "are we affected by CVE-2026-xxxx?" → vuln-check
- "fix the vulnerabilities" → vuln-fix
- "set up vulnerability scanning for this repo" → vuln-setup

Or run the scanner directly:
```bash
node vuln-check/scripts/scan.mjs --path path/to/repo          # prints report, writes .vuln-guard/reports/report.md + .json
node vuln-check/scripts/scan.mjs --path . --fail-on critical  # CI gate
node vuln-check/scripts/scan.mjs --path . --sarif vuln.sarif   # optional: SARIF for GitHub code scanning
node vuln-check/scripts/scan.mjs --help
```

Exit codes: `0` ok · `1` findings at/above `--fail-on` · `2` tool error · `3` could not reach any advisory source (only with `--fail-on`).

## Company laptops

- **PowerShell execution policy doesn't matter** — nothing here is a `.ps1`; `node scan.mjs` runs like any other Node command.
- **Proxy:** `set HTTPS_PROXY=http://proxy:port` and `set NODE_USE_ENV_PROXY=1`. **TLS inspection:** `set NODE_EXTRA_CA_CERTS=C:\path\company-root-ca.pem`. Never turn off TLS verification.
- **Blocked internet:** `--offline` still runs `npm audit` and `dotnet list package --vulnerable` through your company's npm/NuGet mirror, and the report says which ecosystems weren't covered. Or let CI do the scan.
- **Privacy:** only package names + versions are sent to OSV.dev; no source code. List internal package prefixes under `private` in `.vuln-guard/config.json` so they are never sent.
- If Node itself is blocked: `vuln-check/reference/manual-fallback.md` has the equivalent built-in commands.

## Data sources

[OSV.dev](https://osv.dev) (GitHub Advisories, NVD, PyPA, RustSec, Go vulndb, …) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (with GitHub mirror fallback) · [FIRST EPSS](https://www.first.org/epss/) · [endoflife.date](https://endoflife.date) · `npm audit` · `dotnet list package --vulnerable`. Cached for 12–24 h in the system temp folder.

## How it compares

The scanning itself is not new: [osv-scanner](https://github.com/google/osv-scanner), [Trivy](https://github.com/aquasecurity/trivy) and [Grype](https://github.com/anchore/grype) read the same lockfiles and the same OSV/GitHub advisory data, and Dependabot opens update PRs for free on GitHub. Use them if you can.

vuln-guard is for the gaps around them:

- **Nothing to download.** One Node script, no binary. Works on locked-down laptops where installing scanners is not allowed but Node is.
- **Agent workflow, not just a list.** The skills tell the agent how to check the result is real (offline ≠ clean), rank by exploitation (CISA KEV, EPSS), apply only safe patch/minor upgrades, build, test, re-scan, and leave the commit to you.
- **Runtimes and base images.** Flags end-of-life or behind-patch .NET, Node, Python, Go and Docker base image tags.
- **One prompt sets up CI** for GitHub Actions, Azure Pipelines or GitLab, plus Dependabot and NuGet Audit.

## Tests

```bash
node --test test/scan.test.mjs                 # offline
VG_ONLINE=1 node --test test/scan.test.mjs     # also queries OSV.dev
```

## Limits

Known advisories only — not a code scanner, secret scanner or pentest. Container OS packages are not scanned (use Trivy / Docker Scout). Maven `pom.xml` is direct-only without a lockfile. Binary `bun.lockb` isn't readable (text `bun.lock` is). Go standard library is checked only when go.mod has a `toolchain` line (the `go` line is just a minimum); otherwise use `govulncheck`.
