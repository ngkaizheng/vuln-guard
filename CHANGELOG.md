# Changelog

## 1.1.0 — 2026-10-23

Added
- Claude Code plugin: `/plugin install vuln-guard --marketplace ngkaizheng/vuln-guard`. Codex reads the same marketplace.
- `bun.lock` (text lockfile, Bun ≥ 1.2). A binary `bun.lockb` is reported as a gap.
- Go standard library CVEs, read from the go.mod `toolchain` line. A move to a newer Go line counts as a major upgrade.
- `pnpm audit` cross-check, next to `npm audit` and `dotnet list package`. It also works with `--offline` through a company npm mirror.
- pnpm: transitive packages that are reachable only from devDependencies are marked dev-only, so their priority is lowered.
- `--sarif <file>`: SARIF 2.1.0 output for GitHub code scanning, including runtime and base-image issues. It is opt-in.
- Severity is borrowed from GHSA or Bitnami aliases when an OSV record has none. On the test fixture, unrated Go advisories dropped from about 50% to about 1%.
- `scripts/validate.mjs` checks skill frontmatter, links, version sync and the zero-dependency rule in CI.
- `--no-local`: leave out runtimes installed on the scanning machine (the CI templates use it).
- `examples/demo-app` and its sample [REPORT.md](examples/demo-app/REPORT.md).

Fixed
- A clean `npm audit` or `dotnet list package` result now counts as "verified". Before, only tools that found something counted, so a clean project read as "NOT VERIFIED" whenever OSV was unreachable.
- Windows: `dotnet` no longer runs through a shell. Repo paths with spaces or `&` used to break the command or could inject commands.
- Runtimes: one row per runtime line across projects. A version such as "3.12" is no longer reported as behind on patches.

Changed
- Runtime advice recommends the newest **LTS** line where the product has LTS releases (Node 24, not Current 26).
- Skills moved to `skills/` (the layout that skill installers and plugin marketplaces expect). `install.mjs` and `npx skills add` keep working.

## 1.0.0 — 2026-10-23

First public release: `vuln-check`, `vuln-fix` and `vuln-setup` skills, plus a zero-dependency Node scanner (OSV.dev, CISA KEV, FIRST EPSS, endoflife.date, npm audit, dotnet list package).
