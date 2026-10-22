# Manual fallback (no Node.js, or the script is blocked)

Run whichever apply, collect the results, and present them in the same shape as the normal report (priority, package, current → fixed, CVE/GHSA, severity, direct/transitive, file). Then look up each CVE in the CISA KEV catalog (https://www.cisa.gov/known-exploited-vulnerabilities-catalog) to mark actively exploited ones as P0.

| Ecosystem | Command | Notes |
|---|---|---|
| .NET | `dotnet list <sln> package --vulnerable --include-transitive` | Run `dotnet restore` first. Add `--format json` (SDK 7.0.200+) for machine-readable output. Built into the SDK, works through the company NuGet feed. |
| .NET (build-time) | `dotnet restore` shows `NU1901–NU1904` warnings | NuGet Audit; set `NuGetAuditMode=all` to include transitive packages (default from the .NET 9 SDK). |
| npm | `npm audit --json` | `--omit=dev` for production only |
| pnpm | `pnpm audit --json` | |
| Yarn Berry | `yarn npm audit --all --recursive --json` | classic: `yarn audit --json` |
| Python | `pip-audit -r requirements.txt` | `pip install pip-audit` |
| Go | `govulncheck ./...` | also tells you whether vulnerable code is actually reachable |
| Rust | `cargo audit` | `cargo install cargo-audit` |
| Ruby | `bundle exec bundle-audit check --update` | |
| PHP | `composer audit` | Composer 2.4+ |
| Java | OWASP Dependency-Check (`mvn org.owasp:dependency-check-maven:check`) | slow first run (downloads NVD) |
| Everything | `osv-scanner scan source -r .` | Single binary from github.com/google/osv-scanner (Windows .exe available), same OSV data as the script |

Runtime EOL by hand: https://endoflife.date/dotnet , /nodejs , /python , etc. Compare with `dotnet --list-runtimes`, `node --version`, and the tags in Dockerfiles.

## When PowerShell scripts are blocked on a company laptop

The skills never need PowerShell scripts. `node scan.mjs` is not affected by PowerShell execution policy. If even Node is blocked:
- run the built-in tools above from `cmd.exe` (they are executables, not scripts), or
- run the scan in CI instead (see `vuln-setup` templates) and read the uploaded report.
