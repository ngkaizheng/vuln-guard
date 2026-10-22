## What and why

## Checklist
- [ ] `node --test test/scan.test.mjs` passes (and `VG_ONLINE=1` if the change touches matching or ranking)
- [ ] `node scripts/validate.mjs` passes
- [ ] No new dependencies, and the scanner is still one file
- [ ] New lockfile format or behaviour → fixture + test, docs row, fix recipe
- [ ] User-visible change → `CHANGELOG.md`
