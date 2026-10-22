# STATUS

Updated 2026-10-23.

## Done
- Public repo: https://github.com/ngkaizheng/vuln-guard (MIT).
- Install works: `npx skills add ngkaizheng/vuln-guard` (checked from GitHub) and `node install.mjs`.
- Scanner verified on 4 real local repos (npm, uv, pip, .NET + npm audit + dotnet list package). Results match npm audit.
- Fixed: Windows shell injection / spaces in paths for `dotnet`; duplicate runtime rows; "3.12" reported as patch-behind.
- Tests + CI (Ubuntu/Windows × Node 18/22).
- PR #1: bun.lock, Go stdlib (toolchain line only), alias severity for Go advisories, opt-in `--sarif`.
- vuln-fix end-to-end on CoCoPet (branch `security/vuln-fix-20261023`, uncommitted): 11 → 2 findings, matched `pnpm audit` exactly, tests + build pass. Recipe note: `pnpm update <pkg>` takes the newest in range (browserslist 4.29.4, not 4.28.7).

## Open
- See TODO.md: company proxy laptop, real Claude Code / Copilot trigger test, vuln-setup and vuln-fix end-to-end.
- Ideas: run `pnpm audit` as a native cross-check (only npm audit today); mark pnpm/bun transitive dev-only deps (tailwind chain shows as prod); Claude Code plugin marketplace (wait until value is confirmed).
