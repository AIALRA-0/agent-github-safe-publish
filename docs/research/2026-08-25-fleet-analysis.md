# AIALRA-0 仓库敏感信息分析

## 1. 审计结论

GitHub 是本轮仓库母集和设置状态的数据来源

根据公开聚合文件 [1]，截至 2026-08-25，GitHub 当前接口返回 93 个 `AIALRA-0` 直接拥有的仓库

公开聚合文件 [1] 记录其中 71 个公开、22 个私有，仓库总数计算如下：

$$
71 + 22 = 93
$$

根据用户本次确认的计划，计划冻结时的仓库数为 91

按当前母集与计划母集计算，仓库数量变化如下：

$$
93 - 91 = 2
$$

审计执行前新增了 2 个仓库，因此本轮采用当前完整母集

公开聚合文件保存了复算所需的计数 [1]

公开聚合文件 [1] 显示，93 个仓库中有 91 个结论为 `incomplete`，2 个结论为 `block`，没有仓库达到 `pass`

`incomplete` 表示至少一个声明表面缺少完整读取或解析能力

这个状态只证明存在覆盖缺口，无法支持有效凭据或仓库安全结论

## 2. 现有脱敏方式

公开聚合文件 [1] 记录审计前的 78 个本地同步目录采用了多种独立做法

公开聚合文件 [1] 显示，其中 13 个仓库包含 Gitleaks 配置，18 个仓库包含持续集成安全工作流，42 个仓库通过忽略规则排除 `.env`

这些数量来自 2026-08-25 的本地受控文件清单 [1]

Gitleaks 是扫描目录和 Git 历史凭据模式的工具，本轮固定使用 v8.30.1

持续集成（Continuous Integration，CI）在代码变更后自动运行检查，失败日志如果包含原文会造成二次泄漏

现有实现主要分为以下路径：

- Gitleaks 全历史扫描并遮蔽报告
- pre-commit 提交前检查，只覆盖暂存变更
- 自定义正则检查凭据、邮箱、IP 与本机路径
- 已知泄漏值的摘要阻断
- 数据库、日志和个人文件名阻断
- 仓库专属允许项与 CI 影子门禁

不同实现对 Git 历史、二进制、LFS、Release 附件、日志输出和允许项的处理并不一致

部分自定义扫描器会输出命中原文，部分扫描器跳过源代码或二进制，部分扫描器只看当前变更

因此现有门禁适合作为补充规则，不能独立代表统一覆盖

## 3. 候选分布

公开聚合中的 `finding_counts_by_rule` 各项求和得到无原文发现记录总数：

$$
F = \sum_r n_r = 637{,}105
$$

其中 $n_r$ 表示规则 $r$ 的命中次数

本机候选文件记录 347,578 条原文候选，该数值来自 `candidate_count`

两者数量不同，因为 Gitleaks 只进入遮蔽报告，跨表面发现也可能不生成新的原文候选

下列数量是规则命中次数，不能当作独立人员、独立凭据或已经确认的隐私事件 [1]

<div align="center">

| 规则范围 | 命中次数 |
|---|---:|
| URL | 496,124 |
| 邮箱 | 44,612 |
| IP 地址 | 37,506 |
| `AIALRA` 私有品牌规则 | 22,707 |
| 疑似凭据赋值 | 22,069 |
| UID 与账号标识 | 4,266 |
| 电话号码 | 4,059 |
| 本机绝对路径 | 3,588 |
| 数据库连接地址 | 1,417 |
| 详细英文地址 | 338 |
| 数据库制品 | 220 |
| 签名 URL | 97 |
| Gitleaks 遮蔽候选 | 81 |
| 私钥头 | 21 |

表 3.1 主要候选命中次数

</div>

注：URL、邮箱和 IP 中包含公开依赖、第三方作者与文档示例，需要信息所有者在本机按精确位置复核

已经公开的有效凭据需要先撤销或轮换

删除文件行或仓库本身不能让已经复制的凭据失效 [2]

## 4. 容易遗漏的信息

Git 大文件存储（Git Large File Storage，LFS）把大文件实体与普通 Git 指针分开保存

只扫描普通 Git 内容会遗漏这些实体

本轮覆盖缺口集中在普通凭据扫描器较少处理的表面：

- Git 已删除文件、分支、标签、作者邮箱、提交消息和旧对象
- LFS 实体、子模块 URL 与固定提交、仓库描述、主页和主题
- GitHub Release 附件、嵌套压缩包、加密归档和超大制品
- 图片像素、二维码、EXIF 图像元数据、缩略图、PDF 文档和 Office 作者属性
- Notebook 运行输出、数据库转储、日志、HAR 网络记录、崩溃文件、提示词和 Agent 会话
- 签名 URL、数据库连接凭据、本机绝对路径、设备 ID 和跨文件可关联 UID
- LICENSE、NOTICE、CITATION、第三方作者和来源链
- 扫描器自身的标准输出、错误输出与 Actions 日志

NIST 美国国家标准与技术研究院（National Institute of Standards and Technology）的去标识化资料把自由文本和多媒体纳入个人信息处理范围 [3]

因此只扫描源代码字符串会遗漏可重新识别的信息

## 5. 覆盖缺口

公开聚合文件 [1] 显示，Git 历史产生 5,893 个不可读对象事件和 11 个工具失败事件

主要原因包括 3,516 个待复核二进制、2,294 个不透明二进制、49 个超大对象、15 个浅克隆历史、3 个单仓库历史预算超时、2 个 Git 对象枚举失败和 6 个发现数量上限事件 [1]

Release 表面中，84 个仓库没有 Release 附件，9 个仓库至少读取了附件

同一表面记录了 61 个归档成员上限事件和 79 个不可读或超大附件事件

LFS 表面中，91 个仓库没有 LFS 实体，2 个仓库的 LFS 枚举失败

子模块表面中，3 个仓库存在并完成枚举，90 个仓库没有子模块 [1]

GitHub 历史清理会影响签名、拉取请求、fork 和旧克隆

因此本轮没有执行历史重写或强制推送 [4]

## 6. GitHub 补充防线

Secret Scanning 是 GitHub 提供的凭据模式检查

Push Protection 在提交进入仓库前阻止受支持的秘密

仓库级设置接口显示 64 个仓库同时启用这两项能力，7 个公开仓库同时关闭，22 个私有仓库的字段不可用 [1]

REST 表述性状态转移（Representational State Transfer）接口没有返回用户级 Push Protection 字段

已登录设置页也无法访问，因此用户级状态保持 `unknown`

Gitleaks v8.30.1 已通过官方校验和下载，并在 93 个仓库上使用完整遮蔽报告 [5]

GitHub 支持的凭据模式只覆盖特定秘密类型，无法替代个人信息、二进制元数据和私有精确标识检查 [6]

## 7. 本轮边界

本轮首次审计覆盖 Git、LFS、子模块指向、仓库元数据和 GitHub Release 附件

Issue、拉取请求正文与评论、Discussion、Wiki、GitHub Pages、历史 Actions 日志与产物、Packages、容器镜像、缓存、Gist 和外部克隆仍未检查

详细报告与候选原文只保存在 `CODEX_HOME/private/github-safe-publish/`

信息所有者完成本机复核与修复确认后，应删除原文候选和详细报告

后续只保留不含仓库名、路径和标识的聚合统计

## 8. 参考文献

[1] AIALRA-0, [Fleet summary without repository names, paths, or identifiers](fleet-summary.public.json), 2026-08-25

[2] GitHub, [Remediating a leaked secret in your repository](https://docs.github.com/en/code-security/tutorials/remediate-leaked-secrets/remediating-a-leaked-secret), 2026-08-25 访问

[3] NIST, [IR 8053 De-Identification of Personal Information](https://csrc.nist.gov/pubs/ir/8053/final), 2026-08-25 访问

[4] GitHub, [Removing sensitive data from a repository](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository), 2026-08-25 访问

[5] Gitleaks, [Official repository](https://github.com/gitleaks/gitleaks), 2026-08-25 访问

[6] GitHub, [Supported secret scanning patterns](https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns), 2026-08-25 访问
