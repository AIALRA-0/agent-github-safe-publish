# GitHub 安全发布

`github-safe-publish` 为 Agent 提供统一的仓库脱敏标准、私有策略合同和发布停止条件。它检查工作区、Git 历史、Git LFS 大文件、子模块、仓库元数据和 GitHub Release 附件，并且只在所有声明表面都完整检查且没有未处置发现时返回 `pass`。

公开仓库只保存通用规则、合成测试和无敏感值的工作流。候选原文与私有匹配策略保存在 `CODEX_HOME/private/github-safe-publish/`，不会写入 GitHub Actions 日志或公开报告。

## 1 使用方式

- Agent 使用 `$github-safe-publish` 读取完整授权边界和处置流程
- 操作者运行 `python scripts/safe_publish.py --help` 查看审计、候选、隔离副本和门禁命令
- 仓库维护者先采用影子工作流，完成真实变更和事故演练后再决定是否启用强制规则

`review`、`block` 和 `incomplete` 都会返回失败状态。只有 `pass` 允许进入已经获得授权的 GitHub 发布步骤。

## 2 当前边界

工具不会自动重写 Git 历史、作者、标签、签名、许可证、引用记录或现有 Release。PDF、图片和其他无法完整解析的二进制必须取得精确摘要批准，否则检查结果为 `incomplete`。

## 3 参考资料

- [GitHub：Remediating a leaked secret](https://docs.github.com/en/code-security/tutorials/remediate-leaked-secrets/remediating-a-leaked-secret)
- [GitHub：Removing sensitive data](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [NIST IR 8053](https://csrc.nist.gov/pubs/ir/8053/final)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
