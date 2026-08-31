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

## 4. 安全问题

公开 Issue 不能承载真实漏洞证据；请按照 [`SECURITY.md`](SECURITY.md) 使用 GitHub 私密漏洞报告
