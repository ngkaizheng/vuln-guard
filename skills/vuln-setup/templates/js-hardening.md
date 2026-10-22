# JavaScript supply-chain hardening

Most npm incidents in 2025–2026 were malicious *new versions* of real packages (stolen maintainer tokens, self-spreading worms) and typosquats, usually executing through install scripts. These settings reduce that risk. Add only what fits the project, and explain each line to the user.

## All package managers

- Commit the lockfile. In CI install exactly from it: `npm ci` · `pnpm install --frozen-lockfile` · `yarn install --immutable`.
- Never "fix" a lockfile conflict by deleting the lockfile and reinstalling — that silently upgrades hundreds of transitive packages.
- Keep long-lived npm/GitHub tokens off developer machines and CI where possible; use short-lived / scoped tokens.

## npm — `.npmrc` (project root)

```ini
# `npm audit` exits non-zero only for high/critical
audit-level=high
# Optional, strongest protection: don't run dependency install scripts.
# Packages that genuinely need them (esbuild, sharp, prisma, husky, node-gyp builds…)
# must then be built explicitly: `npm rebuild esbuild sharp`.
# ignore-scripts=true
```

## pnpm — `pnpm-workspace.yaml`

pnpm 10+ does not run dependency install scripts unless allow-listed:
```yaml
onlyBuiltDependencies:
  - esbuild
# Don't install versions published less than a day ago (pnpm >= 10.16):
minimumReleaseAge: 1440
```
Check `pnpm --version` before adding `minimumReleaseAge`.

## Yarn Berry — `.yarnrc.yml`

```yaml
enableScripts: false   # then allow-list per package via dependenciesMeta.<name>.built: true in package.json
```
