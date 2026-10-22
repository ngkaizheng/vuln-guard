# Supported ecosystems and files

The scanner walks the project (skipping `node_modules`, `bin`, `dist`, `.git`, `vendor`, `.venv`, `target`, …) and reads:

| Ecosystem | Files read | Notes |
|---|---|---|
| npm | `package-lock.json` (v1–v3), `npm-shrinkwrap.json`, `package.json` | `npm audit --package-lock-only` also runs when npm is installed |
| pnpm | `pnpm-lock.yaml` (v5, v6, v9) | |
| Yarn | `yarn.lock` (classic v1 and Berry) | |
| NuGet / .NET | `obj/project.assets.json` (full graph after restore), `packages.lock.json`, `*.csproj` / `*.fsproj` / `*.vbproj`, `Directory.Packages.props` (central package management, `VersionOverride`, `$(Property)` versions), `packages.config` | `dotnet list package --vulnerable --include-transitive` also runs when the SDK is installed |
| PyPI | `requirements*.txt` / `constraints*.txt` (pinned `==` lines), `poetry.lock`, `uv.lock`, `Pipfile.lock` | Unpinned requirement lines (`>=`) are listed as gaps |
| Go | `go.mod` (require blocks, `// indirect`) | `go` / `toolchain` directive checked for EOL |
| Rust | `Cargo.lock` | workspace crates skipped |
| Ruby | `Gemfile.lock` | Ruby version from `RUBY VERSION` |
| PHP | `composer.lock` | |
| Java | `pom.xml` (direct deps, `${property}` resolved), `gradle.lockfile` | Plain `build.gradle` without lockfile is reported as a gap |
| Dart/Flutter | `pubspec.lock` | |

## Runtimes and base images

| Signal | Example |
|---|---|
| `<TargetFramework(s)>` | `net8.0`, `net10.0-windows`, `net48`, `<TargetFrameworkVersion>v4.8` |
| `global.json` | SDK pin (EOL only — the shipped runtime patch comes from the image/server) |
| `Dockerfile` / `Containerfile` `FROM` | `mcr.microsoft.com/dotnet/aspnet:8.0.11`, `node:18-alpine`, `python:3.12-slim`, `nginx`, `postgres`, `redis`, … |
| `docker-compose*.yml` / `compose*.yml` `image:` | same mapping |
| `.nvmrc`, `.node-version`, `package.json` `engines.node` | `engines` is treated as a *minimum allowed*, not what runs |
| `.python-version`, `.ruby-version`, `.tool-versions`, `go.mod` | |
| This machine | `dotnet --list-runtimes`, `node --version` (only when the project uses them) |

Status meanings: `eol` no more security patches · `eol-soon` support ends within ~4 months · `outdated` a newer patch exists in the same line · `warn` floating tag (`latest`) or an allowed-but-EOL minimum · `ok`.

A tag such as `aspnet:8.0` floats to the newest 8.0 patch **when the image is rebuilt and pulled** — a long-running container built months ago is still old. Say this when floating tags are found.
