# sshm

> A pretty, AI-friendly SSH connection manager.

> v0.1 is under active development. See [docs/specs/2026-05-13-sshm-design.md](docs/specs/2026-05-13-sshm-design.md) for the design and [docs/superpowers/plans/2026-05-13-sshm-v0.1.md](docs/superpowers/plans/2026-05-13-sshm-v0.1.md) for the v0.1 implementation plan.

## Release Process (maintainers)

Releases are automated by GoReleaser on tag push. To cut v0.1.0:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

Required repo secrets:

- `HOMEBREW_TAP_TOKEN` — PAT with `contents: write` on `michael-ltm/homebrew-tap`
- `SCOOP_BUCKET_TOKEN` — PAT with `contents: write` on `michael-ltm/scoop-bucket`

## License

MIT — see [LICENSE](LICENSE).
