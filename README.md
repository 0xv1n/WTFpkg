# WTFpkg

**What The F*** Is In Your Packages**

A defensive security resource documenting how package managers can be abused by adversaries. Think [GTFOBins](https://gtfobins.github.io/) but for package manager abuse techniques.

**[Browse Techniques](https://0xv1n.github.io/WTFpkg/)**

## Package Managers Covered

| Manager | Ecosystem | Techniques |
|---------|-----------|------------|
| apt / dpkg | Debian & Ubuntu | Maintainer scripts, GPG bypass, repo injection, MITM |
| pip / PyPI | Python | setup.py execution, dependency confusion, typosquatting |
| npm | Node.js | Lifecycle scripts, dependency confusion, npx abuse |
| RubyGems | Ruby | Native extensions, plugin hooks, gem source manipulation |
| Cargo | Rust | build.rs execution, proc macros, crate extraction |
| Homebrew | macOS | Formula Ruby execution, Cask flight blocks, malicious taps, .pkg privilege escalation |

## Local Development

```bash
# Requires Hugo v0.156.0+ (extended)
hugo server --buildDrafts
```

Site runs at `http://localhost:1313`.

## Contributing

Want to add a technique or a new package manager? See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)