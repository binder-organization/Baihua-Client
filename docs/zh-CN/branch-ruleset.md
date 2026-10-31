# 分支 Ruleset 脚本说明

[`scripts/activate_ci_ruleset.sh`](../../scripts/activate_ci_ruleset.sh) 是一次性配置工具，用 GitHub API 为 `main` 和 `develop` 创建名为 `Human-reviewed CI for main and develop` 的 Ruleset。GitHub Actions 的 CI 和发布工作流不会调用它；是否把这个脚本提交到仓库，不影响工作流运行。

## 它会创建什么规则

- 变更通过 PR 合入，至少获得 1 人批准，并解决审查讨论；新推送会使旧批准失效。
- 必需检查为 GitHub Actions 的 `Lint and test`，且要求分支与目标分支保持最新。
- 禁止强制推送和删除受保护分支。
- 可在运行前用 `BYPASS_USERS` 指定逗号分隔的其他 GitHub 用户名；维护者应先确认这份名单。

脚本不会自动合并 PR，也不会修改 CI 工作流。规则建好后，由 GitHub 在服务器端执行；维护者电脑不需要持续运行脚本。

## 如何执行

维护者可在自己的电脑或其他已配置 `gh` 的终端，取得仓库代码后，从仓库根目录执行。需要 `bash`、`gh`、`jq`，以及具有仓库 Ruleset 管理权限的 GitHub 登录。脚本默认目标是 `GavZheng/Baihua-Client`；如需操作其他仓库，先设置 `GITHUB_REPOSITORY=所有者/仓库名`。

先确认当前 `main` 提交的 CI 已成功，然后运行：

```sh
gh auth status
bash scripts/activate_ci_ruleset.sh
bash scripts/activate_ci_ruleset.sh --apply
```

第二条命令只打印准备提交的规则，供维护者审阅。第三条命令才调用 GitHub API 创建规则。运行 `--apply` 时，脚本会检查仓库自动合并已关闭、CI 工作流在默认分支已启用、当前 `main` 提交的最近一次推送 CI 成功、该提交出现 `Lint and test` 检查，以及同名 Ruleset 尚不存在。检查不通过就退出，不会创建规则。成功后在 GitHub 仓库的 **Settings → Rules → Rulesets** 核对结果；同名规则已存在时，脚本不会覆盖。

## 是否需要提交到仓库

**不需要。**Ruleset 本身保存在 GitHub 仓库设置中，维护者完全可以私下用网页设置或本地脚本创建。把脚本留在仓库的价值，是让规则内容可审阅、可复现，并记录其创建前的检查条件。若团队决定由维护者私下管理，只需保留双方认可的规则要求和操作记录；私下运行脚本与否不会改变已创建的 Ruleset。

这份说明只描述脚本当前行为。仓库文件不能证明 GitHub 上的规则已启用，实际状态以仓库设置为准。
