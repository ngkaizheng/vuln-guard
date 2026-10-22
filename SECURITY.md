# Security policy

vuln-guard runs inside your coding agent with your permissions, so its own safety matters.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private reporting instead: [Report a vulnerability](https://github.com/ngkaizheng/vuln-guard/security/advisories/new). You can expect a first answer within 7 days. A fix for a confirmed issue ships in a patch release with credit to you, unless you ask not to be named.

In scope:
- The scanner (`skills/vuln-check/scripts/scan.mjs`) or `install.mjs` running code, or reading/writing outside the scanned project and its report folder, when it scans a malicious repository (crafted lockfiles, file names, Dockerfiles).
- Sending anything other than package names and versions to the advisory services.
- Skill instructions that would make an agent commit, push, publish, disable security settings, or add ignore rules without the user's explicit decision.

Out of scope: a vulnerability that the scanner *missed* or *reported wrongly* in your project. That is a normal bug. Please open an issue with the "Wrong result" template.

## What the scanner does, so you can check it

- Reads lockfiles and manifests as text. The scanner itself never runs project code or package install scripts.
- By default it also runs `npm audit --package-lock-only`, `pnpm audit` and `dotnet list package --vulnerable` when those tools are installed. **These tools read the repository's own configuration:** `dotnet` evaluates MSBuild files (`*.csproj`, `Directory.Build.props`), and MSBuild property functions can run code. npm and pnpm read the repo's `.npmrc`, which can point to another registry. **For a repository you don't trust, use `--no-native`.** Then the scan is text parsing plus HTTPS requests only.
- Sends package names and versions to `api.osv.dev`, `api.first.org` (EPSS) and `endoflife.date`, and downloads the CISA KEV catalog. Use `private` patterns in `.vuln-guard/config.json` to keep internal package names local, or `--offline` to send nothing.
- Writes only `.vuln-guard/reports/` (or `--out`), plus a cache in the system temp folder.
- It is one file with no dependencies, so it can be read end to end.
