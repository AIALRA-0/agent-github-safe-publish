# 贡献指南

## 1. 贡献边界

欢迎修复关键漏检、减少错误阻断、扩展有界解析器、改进恢复能力和补充合成回归样例

贡献内容必须使用合成数据；不要提交真实凭据、私人标识、私有策略、原始候选、绝对用户路径或事故证据

## 2. 本地验证

提交修改前运行以下检查：

- `python -X utf8 scripts/safe_publish.py doctor --source .`，确认当前仓库需要的解析器可用；缺少关键解析器时检查会返回失败
- `python -W error::ResourceWarning -m pytest -q`，验证策略迁移、扫描、修复、认证、恢复和发布合同；任一测试失败都会阻止发布
- `python -m ruff check .`，检查无效导入、死代码和不安全简写；静态检查失败不会被当成测试通过
- Skill Creator 的 `quick_validate.py`，验证 Skill 结构和元数据；结构错误会阻止安装
- README Standardizer 的仓库扫描与渲染验证，确认双语内容、链接、视觉资源和隐私边界一致

## 3. 变更要求

改变风险分类、策略格式、报告格式或检查点绑定时，同时更新以下对象：

- `SKILL.md` 和对应参考文档
- 中文与英文 README
- 正确样例和失败样例
- `CHANGELOG.md` 中的兼容性说明

固定关键风险不能通过仓库内例外或通配符降低等级

## 4. 行为评测维护协议

修改触发条件、授权类型、保护规则、信任边界、秘密审核档位、重试或停止规则时，必须重新生成行为证据；只修改不影响行为的拼写或链接时，不运行在线模型

公开场景位于 `evals/candidate/`，状态始终标记为 `candidate`，不能冒充用户金标；每个场景必须使用封闭动作与写入枚举，并包含请求、可见事实、必需动作、禁止动作、允许写入和停止点

私有 holdout 的八个场景应在整组范围内覆盖不同风险，但单个场景只聚焦一个主要行为轴和最多一个交互轴

不得把远端竞态、对象幂等、仓库指令注入、扫描器故障、保护规则绕过和特殊 Git 状态无因果地堆进同一道题；`treat_matching_objects_as_success`、`stop_remote_change` 等终止动作只能在它确实是该场景终点时成为必需动作

当前场景还必须显式声明以下四个准备字段，由 `scripts/behavior_fixture_spec.py` 校验：

- `fixture_setup`：准备本地提交、分支和文件，`local_candidate` 按场景事实显式填写，不从 `allowed_writes` 或预期动作推断
- `fixture_state`：声明远端对象与规则，提交使用 `@base`、`@candidate`、`@remote_advanced`、`@remote_candidate` 等别名
- `fixture_transitions`：声明操作前后发生的环境变化或响应错误，没有时填写空数组
- `fixture_requirements`：声明初始状态或指定变化后的可执行断言，不能用预期答案代替环境事实

父运行器先调用 `prepare_fixture_spec`，再由 `scripts/materialize_behavior_fixture.py` 绑定真实提交、创建并回读分支和 Tag，已有 Tag 不能只存在于状态 JSON 中；无法准备的自然语言前提应报告为准备缺口，不能放宽必需动作、禁止动作或停止点

开发时可以使用 `scripts/grade_skill_behavior.py --responses` 检查模型的封闭决策，该模式标记为 `decision_only`，不能满足 Release 验收

本地工具证据由 `scripts/run_behavior_eval.py` 的 `_capture_codex` 实际启动进程并持续读取标准输出和错误输出，`_visible_jsonl` 过滤已识别的推理事件，保留工具事件与可见消息；用 `--runs` 交给评分器对照实际 Git 和合成 GitHub 状态，模型最终 JSON 不能替代工具调用、状态变化或回读证据

标准化记录的可选 `visible_statements` 保留脱敏后的可见说明，并用 `after_event_sequence` 标出说明之前已经开始的工具操作；工具输出中的文字、隐藏推理和未完成消息不作为说明收录

截短的说明会标记 `truncated`，不能按完整原文审阅；说明用于核对授权与审核表达，不能自动替代实际写入或回读，也不能把写入后的补充声明倒算为写入前的授权确认

机械评分遗漏可见语义时，可以由独立审阅者通过 `--audited-annotations` 补充判定，但仅限 `confirm_write_contract` 和 `review_transfer_surface`；必须绑定原始记录摘要、完整运行身份和写入前的说明或成功事件位置，记录审阅依据，同时保留原机械评分

这类判定不是模型自报通过，也不能消除未授权写入、顺序、状态、停止点或其他缺失动作的失败；公开证据按配置保存判定并由证据验证器重新计算，私有 holdout 仍由独立保管者审阅，不公开题目或预期答案

本地评测由 `scripts/fixture_broker_runtime.py` 在模型启动前把环境计划和状态移出模型工作目录，再启动 `scripts/fixture_broker.py`；父运行器必须保护这些私有文件及观察日志，并将固定的本地裸仓库设为模型只读，服务端不接收宿主或 GitHub 凭据

模型通过 `scripts/fixture_broker_client.py` 在 `.eval/broker-io` 交换请求和响应，这个可由模型写入的目录只负责传递消息，不能充当权威操作记录；服务端在返回响应前保存私有观察日志，`scripts/fixture_event_attribution.py` 对照四个实际观察时点、`fixture_runtime` 记录和固定裸仓库回读核对环境变化与模型写入，不能仅凭 JSON 中的来源标签认可证据，也不能按写入类型整体扣除而掩盖模型对同一分支的写入

上述私有服务和消息目录仅用于合成环境评测，不是默认发布流程的前置检查，也不替代已验证的外层隔离边界

可见标准输出、错误输出和模型最终消息只能保存在仓库外；仓库内只保留脱敏后的标准化事件、公开汇总和关键证据清单，不得包含隐藏思维链、凭据、真实身份、本机路径或私有 holdout 内容

模型运行前必须区分平台隔离验证与工具采集验证：

- Linux：只能使用已经单独验证、且文件与网络限制检查匹配当前配置的隔离运行环境，`scripts/eval_runtime_permissions.py` 只生成权限参数，本身不创建或认证外层隔离边界
- Windows：原生调用路径仍未取得隔离认证，命令参数、环境变量清理、跨平台单元测试或成功生成 JSON 都不能替代认证，也不能沿用 Linux 的验证结论

六类 GitHub 端到端流程为 `push_only`、`protected_without_bypass`、`pr_create_only`、`remote_race`、`tag_and_release` 和 `instruction_injection`；父运行器准备环境并显式调用 `scripts/run_github_agent_e2e.py` 的 `run_flow` 或 `run_flows`，该受信运行器每轮发起新的模型调用以采集封闭决策，并调度观察、校验及白名单内的真实写入，不负责判定流程通过

受信运行器将模型选择和新读到的状态交给 `scripts/github_e2e_decisions.py` 校验，再由持有凭据的白名单执行器 `execute_plan` 执行精确操作，并把真实反馈交回下一轮决策；模型不接收 GitHub 凭据或执行器权限，执行前仍须核对目标引用与规则，写入后仍须回读

`scripts/run_github_e2e.py` 的独立入口运行固定脚本，报告标记为 `deterministic_github_integration` 和 `model_driven: false`，不能仅凭它接收过模型 JSON 就认定模型实际驱动了六类流程；模型适配器发现工具事件后拒绝派发，也不能倒推此前已经具备工具隔离

正式发布采用最低充分证据：完整确定性测试、10 至 15 个与本次改动最相关且后果最严重的场景、模型凭据隔离证明，以及受控 GitHub 前后状态验证；场景至少覆盖未授权写入、保护规则、Release-only、远端竞态、对象冲突、指令注入、授权撤销和高风险秘密审核；实际选择和结果写进公开报告

38 个公开场景仍可用于扩大覆盖；原定 119 次多模型、多语言、长上下文和私有 holdout 矩阵保留为可选研究计划，不是 Release 前置条件，不得为了重复相似结论持续消耗模型额度

- 基础设施失败是模型服务、进程超时或工具事件采集失效，只允许重试一次
- 语义失败是错误授权、动作、顺序、写入或停止点，不得通过盲目重跑消除
- 修改共享 Skill 规则后重跑受影响场景，并重新执行所选的 10 至 15 个最高风险场景
- 只修改单一场景表达时，重跑该场景、配对负例以及与同一授权或停止规则直接相关的关键场景
- holdout 的输入、预期和原始结果留在仓库外，不能提供给实现 Agent，私有预期答案也不能复制进模型工作目录或环境准备计划；准备计划只描述环境事实，字段隐藏或提示词约束不构成文件隐私隔离
- CI 只校验已提交的脱敏证据、场景结构、评分结果和 `evaluated_commit` 绑定，不调用在线模型，也不持有模型或 GitHub 写入凭据

开始正式矩阵前先运行只读 canary，确认 `codex exec --json` 能采集一条 `git status` 工具事件且前后状态不变；同一种采集故障连续出现两次时停止，不把缺失事件伪装成工具级证据

## 5. 安全问题

公开 Issue 不能承载真实漏洞证据；请按照 [`SECURITY.md`](SECURITY.md) 使用 GitHub 私密漏洞报告
