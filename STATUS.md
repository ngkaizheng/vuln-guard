# STATUS

Updated 2026-10-23.

## Where it stands
- Public repo: https://github.com/ngkaizheng/vuln-guard (MIT), version 1.1.0.
- Install: `/plugin install vuln-guard --marketplace ngkaizheng/vuln-guard` (Claude Code), `codex plugin marketplace add ngkaizheng/vuln-guard`, `npx skills add ngkaizheng/vuln-guard`, or `node install.mjs`.
- Accuracy: 9 real local projects, OSV-only mode vs each package manager's audit → 151/152 (package, advisory) pairs match. The one difference is an advisory withdrawn on 2026-10-22. Only npm, pnpm and NuGet are benchmarked.
- vuln-fix tried end to end on CoCoPet: local branch `security/vuln-fix-20261023`, **uncommitted**, PR text in `E:\CoCoPet\.vuln-guard\reports\PR_DESCRIPTION.md`. 11 → 2 findings, including 2 critical Next.js RCEs fixed by next 16.4.1. Tests 170/170 and build pass. The user still has to review, commit and redeploy.
- CI: validate job (frontmatter, links, version sync, zero deps) + tests on Ubuntu/Windows × Node 18/22 with live OSV, weekly.

## Decisions made
- Zero dependencies, one scanner file (see CONTRIBUTING.md). Top skill repos are plain markdown + small scripts too.
- Go stdlib only from `toolchain` (the `go` line is a minimum, so it gave false positives).
- SARIF is opt-in (`--sarif`). Company environments may block the upload, but the flag costs nothing when it isn't used.

## Open / next
- Not yet tested: company proxy laptop; real Claude Code / Copilot trigger test of the skills; vuln-setup end to end on a test repo.
- Benchmark PyPI (pip-audit), Go (govulncheck) and Cargo (cargo audit) on real projects.
- Ideas: `osv-scanner`-compatible JSON output; Yarn Berry / Bun dev-only detection; a short demo GIF for the README.
- Growth: the README hook is "are we affected?" for big announced CVEs. Post when the next headline CVE lands (with a real before/after), and submit to awesome-claude-skills lists and the official plugin directory.
