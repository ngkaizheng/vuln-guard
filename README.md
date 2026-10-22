# vuln-guard

**Ask your coding agent "are we affected?" and get a verified answer, a ranked fix plan, and a tested branch.**

[![test](https://github.com/ngkaizheng/vuln-guard/actions/workflows/test.yml/badge.svg)](https://github.com/ngkaizheng/vuln-guard/actions/workflows/test.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen.svg)
![node: >=18](https://img.shields.io/badge/node-%3E%3D18-blue.svg)

Agent skills for Claude Code, Codex, GitHub Copilot, Cursor and other agents. They find **published, still-unfixed vulnerabilities** in your dependencies, runtimes and Docker base images, and they fix them **without** committing for you. The skills run on one Node.js file with **zero dependencies**, so nothing needs to be installed.

```text
you    › A Next.js RCE was just announced. Are we affected?

agent  › Ran vuln-check (OSV ✓, CISA KEV ✓, pnpm audit ✓ — 463 packages).
         YES. next 16.4.0 has 2 critical, unauthenticated RCEs (GHSA-2464-fhr4-w9xw,
         GHSA-673q-mjm6-r5xr). Fixed in 16.4.1, a patch release with no breaking changes.
         Same upgrade fixes a high DoS in next. 8 more are build-time only (tailwind/postcss).
         Run vuln-fix?

you    › yes

agent  › Branch security/vuln-fix-20261023 (not committed):
         next 16.4.0 → 16.4.1 · postcss → 8.5.23 · browserslist, nanoid (transitive)
         pnpm test 170/170 ✓ · pnpm build ✓ · re-scan: 11 → 2
         Left for you: postcss-selector-parser needs a major (Tailwind 4); braces has no fix yet.
         PR description: .vuln-guard/reports/PR_DESCRIPTION.md
```

<sub>Condensed from a real run on a production Next.js app. The [sample report](examples/demo-app/REPORT.md) shows the full output for a demo project.</sub>

## What you get

| Skill | Ask | What it does | Changes files? |
|---|---|---|---|
| **vuln-check** | "check for vulnerabilities", "are we affected by CVE-…?" | Scans every lockfile, runtime and base image. Ranks by real-world risk: **actively exploited (CISA KEV) first**, then severity and exploit probability (EPSS). Refuses to say "clean" when nothing could actually be checked. | No |
| **vuln-fix** | "fix the vulnerabilities" | Makes a local branch. Applies only safe patch/minor upgrades, using the package manager's own commands. Builds, runs your tests, re-scans and writes a PR description. Major upgrades become a decision list for you. | Yes, **never commits or pushes** |
| **vuln-setup** | "set up vulnerability scanning" | CI gate (GitHub Actions / Azure Pipelines / GitLab) with a weekly re-scan, Dependabot, NuGet Audit, npm/pnpm hardening and agent instructions. | Yes, uncommitted |

## Install

**Claude Code** (plugin):
```text
/plugin install vuln-guard --marketplace ngkaizheng/vuln-guard
```
On Claude Code before 2.1.275: `/plugin marketplace add ngkaizheng/vuln-guard`, then `/plugin install vuln-guard@vuln-guard`.

**Codex** reads the same marketplace:
```bash
codex plugin marketplace add ngkaizheng/vuln-guard
```

**Any agent** with the [skills CLI](https://github.com/vercel-labs/skills) (Claude Code, Codex, Cursor, Copilot, Gemini CLI, OpenCode, …):
```bash
npx skills add ngkaizheng/vuln-guard        # this project
npx skills add ngkaizheng/vuln-guard -g     # every project
```

**GitHub Copilot in VS Code** (Agent mode), or no npm access at all:
```bash
git clone https://github.com/ngkaizheng/vuln-guard && cd vuln-guard
node install.mjs                               # ~/.claude/skills (Claude Code + VS Code Copilot)
node install.mjs --copilot                     # also ~/.copilot/skills
node install.mjs --project ../my-repo          # my-repo/.claude/skills: commit it for the whole team
node install.mjs --project ../my-repo --github # my-repo/.github/skills (Copilot cloud agent)
```

Then ask your agent. The skills trigger on their own.

## Does it find the right things?

Results for 9 real projects. vuln-guard ran in OSV-only mode (`--no-native`), compared with each package manager's own audit, counted as (package, advisory) pairs:

| Project | Packages | Package manager's audit | vuln-guard | Same |
|---|---:|---:|---:|---:|
| Next.js app (pnpm) | 463 | 11 | 11 | 11 |
| Hardhat + Solidity tooling (npm) | 588 | 68 | 67 | 67 ¹ |
| React portfolio (npm) | 364 | 14 | 14 | 14 |
| Three.js site (npm) | 227 | 24 | 24 | 24 |
| Next.js marketing site (npm) | 103 | 15 | 15 | 15 |
| Game frontend (npm) | 162 | 11 | 11 | 11 |
| Vite frontend (npm) | 68 | 7 | 7 | 7 |
| RAG web UI (npm) | 201 | 0 | 0 | 0 |
| .NET 10 API + client (NuGet, `dotnet list package --vulnerable`) | 90 | 1 | 1 | 1 |

¹ The one difference is GHSA-hp3w-g68c-fv3c, which was **withdrawn** on 2026-10-22. vuln-guard skips withdrawn advisories.

This comparison covers npm, pnpm and NuGet, the ecosystems that have a built-in audit command to compare against. PyPI, Go, Bun, Cargo and the others are checked by [tests](test/scan.test.mjs) against known CVEs, but have not been benchmarked on real projects yet. A [wrong-result report](https://github.com/ngkaizheng/vuln-guard/issues/new?template=wrong-result.yml) helps.

On top of the audit tools, vuln-guard adds what they don't have:
- **Exploitation data.** CISA KEV and EPSS. The [demo](examples/demo-app/REPORT.md) puts HTTP/2 Rapid Reset (CVE-2023-44487) and a Vite file-read bug at **P0**, because attackers use both today.
- **Every ecosystem in one pass:** npm, pnpm, Yarn, Bun, NuGet, PyPI (pip, Poetry, uv, Pipenv), Go (including the standard library), Cargo, RubyGems, Composer, Maven, Gradle, Pub.
- **Runtimes and base images:** end-of-life or behind-patch .NET, Node.js, Python, Go, Ruby, PHP, nginx, Postgres and similar, from `TargetFramework`, `.nvmrc`, `engines`, `go.mod`, Dockerfile `FROM` and compose `image:`. It recommends the newest **LTS** line.
- **Dev-only detection** for npm and pnpm. Build-tool vulnerabilities are ranked below the ones that ship.

Tested in CI on Ubuntu and Windows with Node 18 and 22, against live OSV and KEV data ([tests](test/scan.test.mjs)).

## Run the scanner directly

```bash
S=skills/vuln-check/scripts/scan.mjs
node $S --path ../my-repo                      # report.md + report.json in my-repo/.vuln-guard/reports
node $S --path . --fail-on critical            # CI gate: exit 1 on critical or actively exploited
node $S --path . --sarif vuln.sarif            # SARIF for GitHub code scanning
node $S --path . --no-native                   # untrusted repo: text parsing + HTTPS only
node $S --help
```

Exit codes: `0` ok · `1` findings at or above `--fail-on` · `2` tool error · `3` no advisory source reachable (only with `--fail-on`).

## Locked-down machines and privacy

- **Nothing to install.** No binary, no `npm install`, no PowerShell script. If Node runs, the scanner runs.
- **Proxy:** set `HTTPS_PROXY=http://proxy:port` and `NODE_USE_ENV_PROXY=1` (Node ≥ 22.21 / 24.5). **TLS inspection:** set `NODE_EXTRA_CA_CERTS=company-root-ca.pem`. Never turn off TLS verification.
- **No internet:** `--offline` still runs `npm audit`, `pnpm audit` and `dotnet list package --vulnerable` through your company's npm/NuGet mirror, and says which ecosystems were not covered.
- **What leaves your machine:** package names and versions, sent to OSV.dev, FIRST EPSS and endoflife.date. Never source code. Put internal package patterns under `private` in `.vuln-guard/config.json` and they are never sent.
- **Untrusted repositories:** use `--no-native`. `dotnet` and npm/pnpm read the repo's own configuration. Details in [SECURITY.md](SECURITY.md).

## How it compares

The scanning itself is not new. [osv-scanner](https://github.com/google/osv-scanner), [Trivy](https://github.com/aquasecurity/trivy) and [Grype](https://github.com/anchore/grype) read the same lockfiles and the same advisory data. Dependabot opens update PRs on GitHub for free. If they fit your setup, use them, and use vuln-setup to add Dependabot.

vuln-guard is built for the part between "a scanner printed 172 lines" and "the fix is merged":
- **It's an agent workflow.** The agent checks that the result is real, explains what matters for *your* project, fixes on a branch, proves it with your own tests, and hands the commit to you.
- **It runs where binaries can't.** A single Node file you can read end to end, for laptops where installing scanners is not allowed.
- **It covers runtimes and base images together with packages,** because an EOL Node 18 image matters more than a moderate ReDoS in a dev tool.

## Limits

- Known, published advisories only. Not a code scanner (SAST), secret scanner or pentest.
- Container OS packages (apt/apk inside images) are not scanned. Use Trivy, Grype or Docker Scout.
- Maven `pom.xml` is direct dependencies only, unless there is a `gradle.lockfile`. Binary `bun.lockb` can't be read; the text `bun.lock` can.
- Go standard library is checked only when go.mod has a `toolchain` line. For call-level reachability, use `govulncheck`.
- Findings are about installed *versions*. Whether your code calls the vulnerable function is something the agent can investigate on request, but the scanner can't prove it.

## More

[Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Supported files](skills/vuln-check/reference/ecosystems.md) · [Fix recipes](skills/vuln-fix/reference/fix-recipes.md) · [Manual fallback without Node](skills/vuln-check/reference/manual-fallback.md)

Data: [OSV.dev](https://osv.dev) (GitHub Advisories, PyPA, RustSec, Go vulndb, …) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [FIRST EPSS](https://www.first.org/epss/) · [endoflife.date](https://endoflife.date). MIT licensed.
