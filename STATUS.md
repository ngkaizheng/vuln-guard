# STATUS

Updated 2026-10-23.

## Done
- Public repo: https://github.com/ngkaizheng/vuln-guard (MIT).
- Install works: `npx skills add ngkaizheng/vuln-guard` (checked from GitHub) and `node install.mjs`.
- Scanner verified on 4 real local repos (npm, uv, pip, .NET + npm audit + dotnet list package). Results match npm audit.
- Fixed: Windows shell injection / spaces in paths for `dotnet`; duplicate runtime rows; "3.12" reported as patch-behind.
- Tests + CI (Ubuntu/Windows × Node 18/22).

## Open
- See TODO.md: company proxy laptop, real Claude Code / Copilot trigger test, vuln-setup and vuln-fix end-to-end.
- Ideas: Claude Code plugin marketplace manifest; `--sarif` output for GitHub code scanning; Go stdlib check; bun.lock.
