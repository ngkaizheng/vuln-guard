# vuln-guard

Agent skills (`vuln-check`, `vuln-fix`, `vuln-setup`) plus one zero-dependency scanner: `skills/vuln-check/scripts/scan.mjs`.
State and next steps: `STATUS.md`. Tests: `node --test test/scan.test.mjs` (add `VG_ONLINE=1` for live OSV). Repo checks: `node scripts/validate.mjs`. Rules for changes: `CONTRIBUTING.md` (zero deps, one scanner file, never report clean when unchecked).

## 术语表

## 术语草稿

- KEV：CISA 公布的“已被黑客实际利用”的漏洞清单；在里面 = P0（待确认）
- EPSS：未来 30 天被利用的概率估计，0–100%（待确认）
- lockfile：记录每个依赖精确版本的文件，如 package-lock.json、uv.lock（待确认）
- transitive（间接依赖）：不是你直接装的，是被别的包带进来的依赖（待确认）
- OSV：Google 维护的开源漏洞数据库，汇总 GitHub Advisories、PyPA、RustSec 等（待确认）
- EOL：end of life，官方停止发安全补丁（待确认）
- SARIF：扫描结果的标准 JSON 格式，GitHub code scanning 读它来显示安全警告（待确认）
- stdlib：Go 标准库，编进程序里，漏洞要靠升级 Go toolchain 修（待确认）
- LTS：长期支持版本（如 Node 24、.NET 10），升级建议优先推荐它（待确认）
- dev-only：只在开发/构建时用、不随产品上线的依赖，优先级降一级（待确认）
- plugin marketplace：Claude Code 的插件目录，用 /plugin install 安装（待确认）
