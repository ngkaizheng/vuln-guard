# TODO — first real-world checks

Automated: `test/scan.test.mjs` (lockfile parsing for npm/pnpm/yarn/pip/NuGet, runtimes, exit codes; online: real OSV matches). CI runs it on Ubuntu + Windows, Node 18 + 22.

Checked 2026-10-23 on Windows 11, Node 22.19, .NET SDK 10: real OSV/KEV/EPSS/endoflife.date, npm audit and dotnet list package on 4 real repos; paths with spaces and `&`. Still open:

- [x] **Real network run** — `node vuln-check/scripts/scan.mjs --path <a real repo>` on the personal laptop. Expect `OSV: ok · KEV: ok` in the header.
- [x] **Real `dotnet list package --vulnerable --format json`** — run on a real .NET solution after `dotnet restore`; confirm the header lists `dotnet list package` and findings show "OSV+dotnet list package".
- [x] **Real `npm audit`** on a React project with a package-lock.json.
- [ ] **Company laptop** — with `HTTPS_PROXY` + `NODE_USE_ENV_PROXY=1` (+ `NODE_EXTRA_CA_CERTS` if needed). If still blocked, check `--offline` gives a partial-coverage report, not "0 vulnerabilities".
- [x] **Windows paths** — run once from cmd.exe / Windows Terminal; check `where npm` / `where dotnet` detection and that file paths in the report look right.
- [ ] **Claude Code** — `node install.mjs`, restart, ask "check this project for vulnerabilities" → vuln-check should trigger.
- [ ] **VS Code Copilot (Agent mode)** — same prompt; confirm the skill is picked up from `~/.claude/skills` (or install with `--project` to use `.claude/skills` in the repo).
- [ ] **vuln-setup on a test repo** — review the generated CI YAML, run one pipeline. Bump action versions in the GitHub template to the current majors.
- [ ] **vuln-fix on a throwaway branch** — confirm it creates the branch, builds, tests, writes `PR_DESCRIPTION.md`, and does not commit.
- [ ] Add your internal package prefixes (e.g. `MyCompany.*`) to `.vuln-guard/config.json` → `private`.

Notes
- `install.mjs --uninstall` removes only the locations you name (add `--copilot` to also remove `~/.copilot/skills`).
- Re-run `vuln-setup` after updating the skills to refresh the project copy `.vuln-guard/scan.mjs`.
