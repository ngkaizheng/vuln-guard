# Contributing

Thanks for helping. The two most useful things are **wrong-result reports** and **new lockfile formats**.

## Ground rules

- **Zero dependencies.** The scanner and the installer use only Node built-ins (`node:` imports) and run on Node 18+. This is what lets vuln-guard work on locked-down machines. CI enforces it.
- **One scanner file.** `skills/vuln-check/scripts/scan.mjs` ships inside the skill and is copied into repos by `vuln-setup`, so it must stay a single self-contained file.
- **Honest output.** Never report "0 vulnerabilities" when nothing was actually checked. If a source fails, say so in `notes`.
- **Skills are instructions, not code.** Keep `SKILL.md` short and imperative. Put long material in `reference/`. A skill must never tell the agent to commit, push or accept risk on the user's behalf.

## Develop

```bash
node --test test/scan.test.mjs                 # offline tests
VG_ONLINE=1 node --test test/scan.test.mjs     # also hits OSV.dev / CISA KEV
node scripts/validate.mjs                      # skill metadata, links, versions, zero deps
node skills/vuln-check/scripts/scan.mjs --path /some/project
```

Adding a lockfile format:
1. Add a parser next to the others in `scan.mjs` and call it from `collect()`.
2. Add a small fixture under `test/fixtures/mixed/<format>/`, plus assertions in `test/scan.test.mjs`: package counts offline, and at least one known CVE online.
3. Add a row to `skills/vuln-check/reference/ecosystems.md` and a fix recipe to `skills/vuln-fix/reference/fix-recipes.md`.

## Wrong results

Please include the scanner output line, the package and version, the advisory ID, and what `npm audit`, `pnpm audit`, `osv-scanner` or your package manager says. A minimal lockfile that reproduces it is gold.

## Releases

Bump `TOOL_VERSION` in `scan.mjs` and `version` in both `.claude-plugin/*.json`, add a `CHANGELOG.md` section, then tag `vX.Y.Z`. `scripts/validate.mjs` fails if these drift apart.
