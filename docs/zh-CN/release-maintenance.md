# CI 与发布维护

## 检查与分支规则

PR 更新及 `main` 推送会触发 `CI`，运行格式检查、Clippy 和测试。非 `main` 分支每周五 00:00 UTC 检查各分支的最新提交。Dependabot 同时按周检查 Cargo 依赖和 GitHub Actions 版本；其更新 PR 由普通 PR CI 检查。

`main` 和 `develop` 的 Ruleset 不会随工作流文件自动启用。先让 `ci.yml` 在 `main` 成功运行，再预览 `bash scripts/activate_ci_ruleset.sh` 的配置，确认后由维护者执行 `bash scripts/activate_ci_ruleset.sh --apply`。规则要求 PR、人工批准和 `Lint and test` 检查；指定维护者可通过 PR 绕过规则。此脚本不会自动合并 PR。

## 版本与发布

CLI、GUI、TUI 分别读取各自 `Cargo.toml` 中的版本，以及对应 `CHANGELOG_CLI.md`、`CHANGELOG_GUI.md`、`CHANGELOG_TUI.md` 中的 `## [版本]` 小节。尚无对应 tag 且有更新日志小节时，`Build Release` 才会构建该产品。三个产品分别使用 `cli-v`、`gui-v`、`tui-v` 前缀；只改代码而不更新版本，不会产生新版本。

发布在 `main` 的 CI 成功后自动触发，也可手动触发。发布前会再次核对当前 `main` 提交的最近一次 CI 结果。GUI 构建包括 macOS、Windows、Linux、Android 和 iOS；目前任一必需平台构建失败都会阻止该次 GUI 发布。iOS IPA 使用临时签名，没有 Apple 描述文件，无法通过常规方式直接安装到 iPhone。

## 失败处理与待确认事项

现有清理脚本按本次运行标记查找 Release，并只删除本次运行管理的 Release 及其拥有的 tag。它不会清空仓库已有的历史 tag 和 Release。维护者提出的“发布出错时删除所有 tag 和 Release”尚未实现；开发者应先明确范围是本次发布涉及的所有产品，还是整个仓库的历史发布，再修改清理逻辑。

检查任务超过 25 分钟、单平台构建超过 35 分钟会显示告警；构建任务的超时上限为 90 分钟。首次启用或调整目标平台后，应在 GitHub Actions 中核对实际耗时、产物及失败清理结果。
