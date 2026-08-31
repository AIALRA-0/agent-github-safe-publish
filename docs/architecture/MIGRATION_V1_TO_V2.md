# GitHub 安全发布从 v1 迁移到 v2

## 1. 行为变化

v1 检查一个候选能否通过；发现关键问题时返回 `deny` 并停止远端写入

v2 把关键问题转换成修复动作；当前候选不能认证时返回修复规划器，只有安全衍生候选获得认证后才进入发布器

<div align="center">

| v1 行为 | v2 行为 | 实际影响 |
| --- | --- | --- |
| `allow`、`allow_with_risk` 或 `deny` 结束检查 | 候选拒绝后返回修复规划器 | 内容风险不再永久结束发布任务 |
| `prepare` 只替换可解码文本 | `sanitize` 执行多类型转换和引用修复 | 路径、数据、文档和制品能够形成安全替代 |
| `managed-publish` 复制后检查 | `run` 审计、修复、验证、复扫、认证并发布 | 主路径真正调用转换器 |
| `preserve-history` 复制私有历史 | 新项目使用安全 Root Commit | 旧私有提交从结构上不可达 |
| Policy v3 表达批准和例外 | Policy v4 表达修复和保留证据 | 私人内容不能靠风险接受进入候选 |
| 暴露面审计参与同一工具叙事 | `exposure` 独立运行 | 舰队风险不阻止单项目安全衍生发布 |

表 1.1 v1 与 v2 行为差异

</div>

## 2. Policy 迁移

v1、v2 和 v3 策略继续只读加载；迁移器在内存中生成 Policy v4，不修改原文件

字段迁移遵循以下规则：

- `identifiers` 迁移为 `sensitive_entities`
- `replacements` 迁移为 `synthetic_mappings`
- `blocked_paths` 迁移为精确 `remove` 对象规则，并要求后续引用修复
- `approved_locations` 只迁移为已经证明公开的 `retention_rules`
- `binary_approvals` 迁移为精确保留、重建或删除证据
- `exceptions` 和 `risk_acceptances` 只保留为审计历史，不能允许私人内容进入候选

旧批准缺少对象摘要、扫描器集合、策略摘要、签发时间或到期时间时，迁移结果进入 `needs_input`

## 3. 命令迁移

- `prepare` 迁移到 `sanitize`
- `gate` 迁移到 `verify`
- `managed-publish` 迁移到 `run`
- `audit-local` 迁移到 `exposure local`
- `audit-fleet` 迁移到 `exposure fleet`

旧命令保留到 v2 稳定版，并在标准错误输出显示迁移入口；旧自动合并在 v1.1.7 起关闭

## 4. 报告迁移

v1 的严格审计字段继续保留在兼容报告中；v2 主报告使用以下对象：

- `SourceFinding`
- `PublicObservation`
- `RemediationAction`
- `CandidateManifest`
- `DegradationReport`
- `VerificationResult`
- `SafetyCertification`
- `PublicationAttestation`
- `WorkflowState`

旧 `deny` 只能表示某个候选未通过旧检查；迁移器不得把它转换成发布任务的永久结束状态

## 5. 回滚

v2 全部工作在隔离候选中进行，源项目保持不变；发布前发生故障时，删除候选即可回滚本地变化

已经快进发布的中央仓库使用后续修复提交回滚；不自动强推、不重写公开历史，也不删除 Release
