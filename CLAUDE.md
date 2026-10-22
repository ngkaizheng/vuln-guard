# vuln-guard

Agent skills (`vuln-check`, `vuln-fix`, `vuln-setup`) plus one zero-dependency scanner: `vuln-check/scripts/scan.mjs`.
State and next steps: `STATUS.md`. Tests: `node --test test/scan.test.mjs` (add `VG_ONLINE=1` for live OSV).

## 术语表

## 术语草稿

- KEV：CISA 公布的“已被黑客实际利用”的漏洞清单；在里面 = P0（待确认）
- EPSS：未来 30 天被利用的概率估计，0–100%（待确认）
- lockfile：记录每个依赖精确版本的文件，如 package-lock.json、uv.lock（待确认）
- transitive（间接依赖）：不是你直接装的，是被别的包带进来的依赖（待确认）
- OSV：Google 维护的开源漏洞数据库，汇总 GitHub Advisories、PyPA、RustSec 等（待确认）
- EOL：end of life，官方停止发安全补丁（待确认）
