
## Dependencies and security

- Before adding or upgrading a dependency, check the project with the `vuln-check` skill (or `node .vuln-guard/scan.mjs --quiet`) and prefer versions without known advisories.
- Check package names exactly before installing — typosquats such as `Newtonsoftt.Json` or look-alike SDK names are a common attack. Prefer packages with an established publisher and download history.
- Do not run `npm audit fix --force`, delete lockfiles to resolve conflicts, or add entries to the `ignore` list in `.vuln-guard/config.json` without an explicit decision from a human.
- Security fixes go on a separate branch and are never committed or pushed by the agent without being asked.
