# CI and Release Process: Maintainer Overview

This document describes the repository's GitHub Actions configuration. The workflows and scripts define the intended behavior. Check the GitHub repository settings to confirm whether the required secrets are configured.

## Routine CI

[`CI`](.github/workflows/ci.yml) runs on pushes to `main` and when a pull request is opened or updated, including when it is reopened, edited, or marked ready for review. It can also be started manually. A new run for a pull request may cancel an older run for the same pull request; runs on `main` are not canceled this way. The workflow has read-only access to repository contents.

The check job is named `Lint and test`. It runs on `ubuntu-latest` with Rust 1.98.1 and executes these commands in order:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

Clippy warnings fail the check. The `--locked` flag requires the committed `Cargo.lock` to be used. The job has a 30-minute timeout and emits a warning if it takes more than 25 minutes. The Rust version is also specified in [`rust-toolchain.toml`](rust-toolchain.toml).

## Builds and Releases

[`Build Release`](.github/workflows/build-release.yml) starts automatically after a successful CI run triggered by a push to `main`. It can also be started manually. It first verifies that the triggering commit is still the current `main` commit and that the latest push CI run for that commit succeeded. It checks again before publication and while making releases public one by one. A CI run for a pull request does not trigger a release. Eligible release runs share a concurrency group to prevent simultaneous publication.

CLI, GUI, and TUI have separate versions, changelogs, and tags:

| Product | Version source | Changelog | Tag |
| --- | --- | --- | --- |
| CLI | `baihua-cli/Cargo.toml` | `CHANGELOG_CLI.md` | `cli-v<version>` |
| GUI | `baihua-client-gui/Cargo.toml` | `CHANGELOG_GUI.md` | `gui-v<version>` |
| TUI | `baihua-client-tui/Cargo.toml` | `CHANGELOG_TUI.md` | `tui-v<version>` |

To release a product, update its version and add a matching `## [version]` section to its changelog. A version with an existing published tag is skipped. A missing changelog section also causes that product to be skipped with a warning. Code changes alone do not republish an existing version. A managed draft release for the same commit can be resumed. Versions containing `alpha`, `beta`, or `rc` are marked as prereleases.

The workflow builds a matrix by target platform. Selected desktop products for the same platform are compiled together. Desktop builds use `cargo build --locked --release`. If any required platform build fails, publication does not start. Each platform job has a 90-minute timeout and emits a warning after 35 minutes.

| Product | Target platforms | Release assets |
| --- | --- | --- |
| CLI | macOS ARM64 / x86_64, Windows x86_64, Linux x86_64 | `.tar.gz` or `.zip` containing the executable and `config/`, plus a standalone executable |
| TUI | macOS ARM64 / x86_64, Windows x86_64, Linux x86_64 | `.tar.gz` or `.zip` containing the executable and `config/` |
| GUI | The desktop platforms above, plus Android ARM64 and iOS ARM64 | macOS `.dmg`, Windows `.msi`, Linux `.AppImage`, Android `.apk`, iOS `.ipa` |

Every installer or archive has a corresponding `.sha256` file. Build jobs verify the assets and checksums, then upload GitHub Actions artifacts with 30-day retention. The publication job downloads all assets, verifies their SHA-256 checksums again, creates draft releases, uploads and reconciles the asset lists, and then makes the releases public one by one. Only the publication and failure cleanup jobs request `contents: write` permission.

### Signing and Installation Limits

- **Android:** If the repository has `CARGO_APK_RELEASE_KEYSTORE_BASE64` and the related password and alias secrets, the APK is signed with the release keystore. Otherwise, it uses a cached debug keystore. A debug-signed APK can be installed but is not suitable for store distribution.
- **macOS:** The `.app` is signed when `CODESIGN_IDENTITY` is set. Otherwise, the DMG is still produced with an unsigned app.
- **iOS:** The IPA is ad hoc signed without an Apple provisioning profile. It cannot be installed on an iPhone through the normal installation process.

### Failed Releases and Recovery

After a failed or canceled publication, the cleanup job finds releases marked with the current workflow run. It deletes only releases managed by that run and tags owned by that run that still point to the expected commit. It does not delete historical releases or tags. Releases for multiple products are made public one by one, so maintainers should check the cleanup result in GitHub after a failure. The cleanup job has a 10-minute timeout. See [`publish_releases.sh`](scripts/publish_releases.sh) and [`cleanup_release_run.sh`](scripts/cleanup_release_run.sh).

## Dependency Updates and Routine Maintenance

[`Dependabot`](.github/dependabot.yml) checks Cargo dependencies and GitHub Actions versions every Friday at 00:00 UTC. Cargo minor and patch updates are grouped. Dependabot pull requests run through the regular pull request CI.

After changing CI or release targets, check actual run times, platform assets, checksum files, signing behavior, and failure cleanup in GitHub Actions. Repository files describe the configuration but do not confirm the live secrets or workflow results on GitHub.
