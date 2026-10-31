# CI and Release Maintenance

## Checks

Pull request updates and pushes to `main` trigger `CI`, which runs formatting checks, Clippy, and tests. Dependabot checks Cargo dependencies and GitHub Actions versions every Friday at 00:00 UTC. Dependabot update pull requests run through the normal pull request CI.

## Versions and Releases

CLI, GUI, and TUI read their versions from their own `Cargo.toml` files and their release notes from the matching `## [version]` sections in `CHANGELOG_CLI.md`, `CHANGELOG_GUI.md`, and `CHANGELOG_TUI.md`. A product is built when it has a changelog section for its version and the matching tag has not been released. The tag prefixes are `cli-v`, `gui-v`, and `tui-v`. Code changes alone do not create a new version when the current version is already tagged.

`Build Release` starts automatically after successful CI on `main` and can also be started manually. Before publishing, it checks the latest CI result for the current `main` commit again. GUI builds target macOS, Windows, Linux, Android, and iOS. A failure on any required target currently prevents that GUI release. The iOS IPA is ad hoc signed without an Apple provisioning profile and cannot be installed on an iPhone through the normal installation process.

## Failure Handling and Open Decision

The current cleanup script finds releases marked with the current workflow run. It deletes only releases managed by that run and tags owned by that run. It does not remove historical repository releases or tags. The requested behavior of deleting all tags and releases when publication fails has not been implemented. Before changing the cleanup logic, maintainers need to define whether “all” means every product involved in the current release or the repository's entire release history.

Checks warn after 25 minutes, and builds warn after 35 minutes per target. Build jobs time out after 90 minutes. When enabling or changing a target platform, verify actual duration, artifacts, and failure cleanup in GitHub Actions.
