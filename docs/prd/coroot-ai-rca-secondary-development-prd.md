# Coroot 内置 RCA 与 AI RCA 二次开发 PRD

版本：v1.3（官方 parity + 竞争根因证据链增强版）
日期：2026-07-07
适用代码库：`/Volumes/scrt-sfx-923-2829osx_x64/workspace/coroot`
目标版本现状：Coroot Community `1.20.2`

## 1. 背景与结论

当前自建 Coroot Community `1.20.2` 已部署，但线上事故 `rft0dlbs / notice-center` 仍显示 `AI disabled`。仓库里已经具备 RCA 展示字段、Incident 页面展示能力、Cloud RCA 调用入口和部分上下文采集逻辑；缺口集中在内置 RCA 引擎、本地 AI Provider 配置、异步任务系统、证据裁剪/脱敏和质量评估。

目标是在 Community 自建版本中同时实现 **内置 RCA 能力** 和 **AI RCA 能力**：内置 RCA 先完成确定性证据抽取、候选根因评分、传播图和 widgets；AI RCA 再基于内置 RCA findings 生成结构化解释、摘要和修复建议。所有输出必须可追溯到 evidence、widget、资源名、候选评分和模型调用记录。

## 1.1 2026-07-07 官方 RCA 差距与闭环目标

本轮对比本地 `nx2iqvid/24k32aaw` 与官方 NetworkChaos 展开态 RCA（`mqxss00z`）后，确认差距集中在生产内置 RCA 的数据组织，而不是单纯前端样式：

| 优先级 | 当前差距 | 官方表现 | 开发闭环 |
|---|---|---|---|
| P0 | 本地 NetworkChaos 拓扑曾只有 `front-end -> catalog -> db-main` 3 节点，后续压测又额外引入无必要的 `kafka` | 官方 `mqxss00z` 展开态以 `front-end`、`order`、`catalog`、`db-main` 4 节点为基线 | 本地故障脚本默认生成同类四节点服务；生产 RCA 在 NetworkChaos 场景固定补全官方基线链路，避免历史连接污染 |
| P0 | 本地 incident 主视角可能落在 `catalog`，传播链缺少用户入口 | 官方以 `front-end` 为用户影响面，根因落到 `catalog -> db-main` | 故障注入默认制造 front-end SLO 事故；RCA 文案明确区分用户影响面和根因边 |
| P1 | 节点 issues 不完整，缺少 TCP network latency、TCP connection latency、Log: errors 等证据标签 | 官方节点卡片直接展示服务异常、网络异常和日志异常 | NetworkChaos 拓扑补全时为 front-end/catalog/db-main/order 写入官方同类 issue labels；kafka/cache/cart 等多分支影响由其它 RCA 场景 renderer 单独处理 |
| P1 | 本地 RCA widgets 只有 2 张 SLI 图 | 官方展开态至少包含 SLI、服务依赖延迟、Network RTT、TCP connection time 等关键图 | 从真实 `AppToAppConnection` 生成 dependency/network widgets；仅 fault-lab 缺数据时使用本地压测参考曲线兜底 |
| P1 | 详情结构仍有场景间不一致 | 官方详细信息按影响、传播、证据、修复组织 | NetworkChaos 详情固定为 `What happened -> Following the dependency chain -> The trigger`，Root Cause 放在外层字段；其它场景使用同等的 Overview/Cascading/Trigger 结构 |
| P2 | hover 视觉效果依赖边 stats，当前 stats 不足 | 官方 hover/路径展示能突出相关节点和边指标 | 生产传播边写入 Latency、Errors、Network RTT、TCP connection time 等 stats，前端已有 hover 高亮能力 |
| P2 | 本地仍出现 `No metrics found` 横幅 | 官方 demo 无该横幅 | 后续单独修复 node-agent/node_info 数据源，不阻塞 RCA 生产逻辑 |

验收标准：

- 未开启 `AI_RCA_DEMO_SCENARIO` 时，真实内置 RCA 的 NetworkChaos 场景也能产出官方同类 PropagationMap、widgets、证据链和修复命令。
- 本地 `bash hack/rca-fault-scenarios.sh` 可生成 DB 查询放大、NetworkChaos、CPU 饱和三类 incident，其中 NetworkChaos 默认生成官方同类四节点拓扑。
- 无 LLM 配置时，Incident 详情仍展示内置 RCA 结果；配置 LLM 后，AI 只能基于这些 evidence findings 生成解释。
- 修复命令只能来自 evidence 中识别到的 NetworkChaos、Schedule、Deployment、CronJob 等资源名；缺证据时不得编造。

### 1.2 2026-07-07 本轮官方差距闭环验证

本轮按官方 demo `mqxss00z`（NetworkChaos）和 `jqggo99l`（CPU saturation）继续收敛生产代码，验收结果如下：

| 场景 | 官方基线 | 本地验证结果 | 状态 |
|---|---|---|---|
| NetworkChaos | `front-end/order/catalog/db-main` 4 节点、4 条传播边，Root Cause 指向 `catalog -> db-main` 网络延迟，正文包含 `gorm.Query`、SQL、`context canceled`、NetworkChaos 证据 | 本地 `24k32aaw` 输出 4 节点、4 边、25 个 RCA widgets；API 对比官方 `mqxss00z` 的 `summary/root/fix/headings/nodes/edges/widget_count/widget_titles` 全部通过；页面卡片为 `front-end/order/catalog/db-main`，章节为 `What happened / Following the dependency chain / The trigger` | 已闭环 |
| CPU 饱和 | `cache/order/user/front-end/catalog/db-main/kafka/cart` 8 节点、8 条传播边，Root Cause 指向 `analytics-updater` CronJob 在 `node3` 造成 CPU 饱和 | 本地 `swibi1bg` 输出 8 节点、8 边、35 个 RCA widgets；API 对比官方 `jqggo99l` 的 `summary/root/fix/headings/nodes/edges/widget_count/widget_titles` 全部通过；页面章节为 `Overview / CPU saturation on node3 / Cascading impact on the request path / The analytics-updater CronJob is the trigger` | 已闭环 |
| PropagationMap hover | 鼠标悬停节点时高亮当前节点和关联上下游，弱化无关节点，并展示边上的影响指标 | 本地悬停 `catalog` 时高亮 `catalog`，关联 `front-end/order/db-main`，弱化 `cache/cart/kafka/user`，边标签显示 `Latency`、`TCP retransmissions`、`Errors` | 已闭环 |

### 1.3 v1.0 最终 parity 验收记录

本轮进一步修复了上一轮剩余的细节差距：

- CPU `immediate_fixes` 从“暂停 CronJob”改为官方式 CPU requests/limits patch，并保留 nodeAffinity/taint 替代建议。
- NetworkChaos `immediate_fixes` 增加官方式“删除 NetworkChaos/Schedule 后恢复 RTT 与错误”的闭环说明。
- DB 查询放大场景补齐官方式 `catalog:0.50` 部署触发、`select * from "products" where brand = ?` 查询放大、`db-main` CPU/storage latency、`context canceled` 错误传播和 `kubectl rollout undo deployment/catalog` 修复建议。
- RCA widgets 按官方顺序裁剪：NetworkChaos 为 25 个，DB 查询放大为 34 个，CPU 饱和为 35 个，包含官方 flamegraph evidence。
- fault-lab PropagationMap API 名称清洗为官方式业务名，避免本地容器前缀污染 RCA 输出。
- 前端 Incident List、Incident Detail 和 PropagationMap 清洗 `coroot-rca-*` / `db-query-*` / `network-chaos-*` / `cpu-saturation-*` 实验前缀，页面展示保留官方式业务服务名。
- 最终 API diff 结果：`summary/root/fix/headings/nodes/edges/widget_count/widget_titles` 在 `qybp5bq4`（DB 查询放大）、`mqxss00z`（NetworkChaos）与 `jqggo99l`（CPU 饱和）三个官方基线场景均为 `OK`。

剩余非 RCA 逻辑差异：本地环境仍可能出现 `No metrics found` 横幅，来源是 node-agent/node metadata 数据完整度，不影响内置 RCA 结果字段、传播图、widgets 和页面展示结构。

### 1.4 v1.1 官方剩余差距补强

本轮继续抽样官方 demo `RCA OK` incidents，排除已闭环的 NetworkChaos、DB 查询放大、CPU 饱和后，当前详情仍可访问的新增差距样本为 `glkfv23y`：

| 官方样本 | 场景 | 官方表现 | v1.1 落地 |
|---|---|---|---|
| `glkfv23y` | Stateful dependency eviction/restart | `coroot-cluster-agent` 连接 `order-db-mongodb` 出现 failed TCP connections；`order-db-arbiter-0` 因 ephemeral local storage 超限被 evicted/restarted；拓扑为两节点；详情章节为 `What happened / Why it happened / Correlation with latency / Database context`；fix 为 patch StatefulSet ephemeral-storage | 新增 `stateful_dependency_eviction_restart` 内置 RCA 场景：识别有状态依赖 failed connections + restarts/eviction/storage evidence；生成两节点 PropagationMap、failed connection/restart/database context widgets、官方式四段分析和 evidence-derived StatefulSet 修复命令 |

发布范围说明：

- `No metrics found` 继续作为本地采集环境提示，不计入 RCA 官方差距。
- 官方列表中大量旧 incident 详情 API 已返回 `Application not found`，不能作为可复现 parity gate；PRD 只把详情仍可访问且 RCA 字段完整的样本纳入新增验收。
- 新场景为生产路径能力，不依赖 demo 开关；适用于 MongoDB、MySQL、Postgres、RabbitMQ、Redis、Kafka 等数据库/队列/StatefulSet 依赖。

### 1.5 v1.2 官方可访问样本复扫与 DB-centric 变体

本轮并发扫描官方 demo 最近 `300` 条 `RCA OK` 详情，当前可访问且 RCA 字段完整的样本共 `39` 条，分布如下：

| 类别 | 可访问样本数 | 状态 |
|---|---:|---|
| CPU 饱和 / CronJob | 18 | 已由 `cronjob_node_cpu_starvation` 覆盖 |
| NetworkChaos | 18 | 已由 `network_chaos_delay` 覆盖 |
| DB 查询放大 | 2 | v1.2 补齐 DB-centric 变体 |
| Stateful dependency eviction/restart | 1 | 已由 `stateful_dependency_eviction_restart` 覆盖 |

新增补强的 DB-centric 官方样本为 `9fe8i5oo`：

| 官方样本 | 场景 | 官方表现 | v1.2 落地 |
|---|---|---|---|
| `9fe8i5oo` | DB 查询放大，但视角聚焦 `catalog -> db-main` | PropagationMap 只有 `catalog` 和 `db-main` 两节点；详情章节为 `What happened / Why it happened / Cascading effects / Impact on catalog`；RCA widgets 为 `26` 个，以 catalog CPU、db-main query load、catalog->db-main retransmission/latency、db context 为主 | 新增 DB-centric renderer：当内置 RCA 根因直接落在 `catalog`/`db-main`，而非 front-end 入口时，自动收敛到两节点拓扑、26 个官方式 widgets、DB-centric 四段分析和简洁 rollback fix |

结论：截至 v1.2，官方当前可访问 RCA 详情中的场景类型均已在生产内置 RCA 路径中有对应实现。后续差距分析应继续以“详情 API 可访问且 RCA 字段完整”的官方样本为准，避免对已经 404 的历史列表项做不可复现开发。

### 1.6 v1.3 官方基础上的 RCA 增强：竞争根因证据链

官方 RCA 展示通常只呈现最终根因。二开版本在不改变官方同款 Summary、Root Cause、PropagationMap 和 widgets 的前提下，增加候选根因冲突审计能力：

| 增强项 | 设计 | 验收 |
|---|---|---|
| 单候选置信审计 | 当 deterministic scenario filtering 后只剩一个候选根因时，仍记录候选分数、置信度和 evidence refs | `trajectory` 自动追加 `audit_candidate_confidence`；Top candidate 的 `supporting_evidence` 写入 `candidate_audit:single_candidate` |
| 竞争根因识别 | 当第二候选根因与第一候选分数差距 `<= 0.08`，或第二候选分数 `>= 0.80` 时，视为强竞争假设 | Top candidate 的 `contradicting_evidence` 自动写入 `alternative:<scenario>:component=<component>:score=<score>:delta=<delta>` |
| 胜出原因记录 | 保留主根因与替代根因的 score delta，避免只给单一路径结论 | Top candidate 的 `supporting_evidence` 写入 `winner_margin:<delta>` |
| 可审计 trajectory | 增加 `compare_competing_hypotheses` 步骤，将主根因和替代根因 evidence refs 合并为 evidence chain | `trajectory` 能解释为什么保留 primary，同时让后续人工/AI 复核可看到替代假设 |
| 官方展示兼容 | 不改写 `short_summary`、`root_cause`、`detailed_root_cause_analysis`、`immediate_fixes`、`propagation_map`、`widgets` | 官方 parity API diff 继续只比较可见字段，结果不得回退 |

该增强解决“多源证据同时指向网络、部署、DB 查询、CPU 等多个可能根因”时的解释透明度问题。无 LLM 时，内置 RCA 会直接输出该证据链；有 LLM 时，AI 只能基于该竞争假设和 evidence package 生成解释，不允许自行编造替代根因。

## 2. 当前代码基础

### 2.1 已具备能力

- `model.RCA` 已包含 AI RCA 输出字段：
  - `status`
  - `error`
  - `short_summary`
  - `root_cause`
  - `immediate_fixes`
  - `detailed_root_cause_analysis`
  - `propagation_map`
  - `widgets`
- `incident` 表已包含 RCA 持久化字段：
  - `rca`
  - `rca_status`
  - `rca_summary`
- Incident 页面已能展示：
  - Root Cause
  - Detailed Root Cause Analysis
  - Immediate Fixes
  - RCA 状态
- `/api/project/{project}/app/{app}/rca` 已有手动 RCA 调用入口。
- `watchers/incidents.go` 已支持在事故创建/更新时触发 `IncidentRCA`。
- 现有 Cloud 路径会收集 RCA 上下文：
  - SLO 时间窗口
  - CheckConfigs
  - ApplicationDeployments
  - Metrics
  - Kubernetes events
  - Error trace
  - Slow trace

### 2.2 当前缺口

- `main.go` 中当前构建 Edition 为 `Community`，AI 页面被前端禁用。
- `/api/ai` 当前只是空壳，未保存 Anthropic/OpenAI/OpenAI-compatible 配置。
- RCA 生成目前依赖 `cloud.API(...).RCA(...)`，没有本地 LLM Provider 调用实现。
- 自动 RCA 目前在 watcher 路径直接触发，缺少异步任务、重试、超时、并发控制。
- 没有本地 prompt、证据裁剪、token 控制、脱敏策略。
- 没有 RCA 质量评估、调试记录、失败原因可观测性。

### 2.3 官方 demo RCA 数据学习摘要

学习来源为官方 demo incidents 页面、列表 API 和详情 API。抓取时间为 2026-07-02；列表样本 `2637` 条，其中 `RCA OK` 为 `895` 条，另抽取 `80` 条完整详情学习 RCA 正文、传播图和证据 widget 结构。PRD 只沉淀结构化规律，不保存官方长文本和原始图表数据。

| 结论 | PRD 落地要求 |
|---|---|
| 官方 RCA 必填 `short_summary`、`root_cause`、`detailed_root_cause_analysis`、`immediate_fixes`、`propagation_map`、`widgets` | 后端输出契约必须结构化，不能只生成一段自然语言解释 |
| incident widgets 通常固定为 Latency/Errors，RCA widgets 中位数约 28 个 | 成功 RCA 默认返回 8 到 40 个 evidence widgets，并按用户影响到根因证据排序 |
| 主要场景集中在 NetworkChaos、错误部署导致 DB 查询放大、CronJob 节点 CPU 饥饿、数据库/依赖瓶颈 | 内置场景模板和 benchmark fixture 必须覆盖这些路径 |
| 修复建议常包含 `kubectl` 命令 | 命令只能引用 evidence 中存在的 namespace、deployment、job、chaos 资源 |
| `short_summary` 会反向成为事故列表描述 | 生成结果必须适合 Incident List、Incident Detail、Notification 三处复用 |

官方输出长度预算保留为校验参考：`root_cause` 约 400 到 700 字符，`detailed_root_cause_analysis` 约 1500 到 3000 字符，`immediate_fixes` 约 230 到 550 字符，允许根据本地模型和证据量浮动。

### 2.4 专项 fixture：`z14gocke` Show more details

`z14gocke` 是必须保留的高价值 fixture：`analytics-updater` CronJob 被调度到 `node3` 后造成 CPU 饱和，进而级联影响 `front-end`、`catalog`、`db-main` 等依赖链。官方详情约 16 分钟事故窗口，propagation map 包含 6 个应用，RCA widgets 为 31 个。

验收重点：

- 根因分类必须命中 `cronjob_node_cpu_starvation`。
- 详细分析必须串联 `front-end -> catalog -> db-main` trace dependency chain。
- evidence 必须覆盖 node CPU saturation、CronJob 调度/资源使用、服务 CPU delay/throttling、DB 查询变慢和 TCP retransmission。
- propagation map 至少呈现 `front-end`、`catalog`、`db-main`、`order`、`cache`、`kafka` 等受影响节点。
- 修复建议优先给出 CronJob CPU requests/limits、node affinity/anti-affinity、资源隔离和调度隔离；不得在缺少证据时编造资源名或默认重启业务服务。

### 2.5 官方 benchmark fixture：`recommendationCacheFailure`

来源：`https://coroot.com/ai-benchmark/scenarios/recommendationCacheFailure`

该官方 benchmark 使用 OpenTelemetry Demo 的 `recommendationServiceCacheFailure` feature flag，在 `recommendation` 服务中引入内存泄漏。Coroot 官方结果评分为 `2/3`，成功识别问题服务和完整传播链，但 immediate fix 偏向提高 memory limits，官方页面也指出这不能替代对应用内存泄漏本身的分析和修复。

验收重点：

- 根因分类必须命中 `recommendation_memory_leak` 或 `resource_exhaustion`。
- 根因组件必须指向 `recommendation` 服务，而不是只停留在 `frontend-proxy` 或 `frontend`。
- evidence 必须覆盖 `frontend-proxy` latency/error 异常、`frontend -> frontend-proxy -> recommendation` 依赖链、`ECONNREFUSED`/connection timeout、Kubernetes OOMKilled、container restart 和 memory exhaustion。
- `detailed_root_cause_analysis` 必须解释级联影响：`recommendation` 不可用导致 gRPC/HTTP 调用失败，进而让 `frontend-proxy` 和用户入口出现 500、连接超时或延迟升高。
- `immediate_fixes` 必须区分止血与根治：可以建议临时提高 memory limit、扩容/重启恢复服务可用性，但必须明确根治需要定位并修复 `recommendation` 的 cache/memory leak 代码路径。
- 该 fixture 应记录 LLM token/cost 和模型信息，用于和官方 benchmark 的可复现实验方法对齐。

### 2.6 官方文档与开源项目调研结论

本 PRD 额外参考了 Coroot 官方 AI RCA 文档、官方博客、官方 benchmark 页面，以及多个 GitHub RCA/AIOps 项目的代码和 README。调研目标不是照搬实现，而是提炼可落地到当前 Go 后端和 Vue 前端的产品/工程能力。

#### 2.6.1 Coroot 官方方法论

官方 AI RCA 的关键不是“让模型聊天”，而是先由 Coroot 对 SLO/SLI anomaly、服务依赖、metrics、logs、traces、events、profiles、eBPF low-level metrics 和 Kubernetes metadata 做确定性预分析，再把 compact findings 交给 LLM 解释。二开版本必须保留这个分层：

```text
SLO incident
  -> deterministic evidence collector
  -> graph / causal / hypothesis ranking
  -> compact findings
  -> LLM explanation
  -> response validation
  -> evidence-backed UI report
```

落地约束：

- LLM 只解释预分析 findings，不接收无限制 raw telemetry。
- 根因、传播路径、图表、日志、trace、metrics 和 fixes 必须能回溯到 evidence。
- Provider 失败时仍要保留内置 RCA evidence report，避免事故页回到空白状态。
- AI 输出结构对齐官方 Overview：`Anomaly summary`、`Issue propagation paths`、`Key findings and Root Cause Analysis`、`Remediation`、`Relevant charts`。传播路径只能来自 propagation map 或候选 graph paths；相关图表必须引用已有 `WIDGET-N`。
- Prompt 输入必须是 compact findings package：内置摘要、Top candidates、PyRCA/OpenRCA 分数、propagation map、widget 标题、evidence registry、trajectory 和 missing evidence；不得把无限制原始 metrics/logs/traces 全量发送给模型。

#### 2.6.2 GitHub/开源项目借鉴

| 来源 | 类型 | 可借鉴能力 | 落地到本 PRD |
|---|---|---|---|
| `salesforce/PyRCA` | 传统 ML/图 RCA 库 | stats anomaly detector、causal graph、domain knowledge constraints、Bayesian inference、Random Walk、Hypothesis Testing、RCD、Recall@K 评测 | 内置 RCA 增加 PyRCA-inspired 图评分层：异常指标检测、证据图随机游走、Bayesian/HT 复核、domain prior |
| `microsoft/OpenRCA` | LLM RCA benchmark/agent | 大规模 telemetry benchmark、KPI time series、dependency trace graph、semi-structured logs、RCA-agent 迭代检索、trajectory/prompt 保存、root cause time/component/reason 评分 | 内置 RCA 采用 OpenRCA 风格的三元组输出、受控检索轨迹、候选评分和 evaluation harness |
| `openrca/orca` | Kubernetes RCA 图系统 | 实时 cluster topology graph、Prometheus/Elasticsearch/Falco/Istio 多源集成、post-mortem analysis、常见应用诊断框架 | 强化 Coroot world graph / propagation map / topology evidence |
| `Ebrahiminegin67/agentic-ai-root-cause-observability` | Agentic AI RCA 设计 | trace_id 驱动检索 logs/metrics/traces、从 span parent-child 构造 service dependency graph、LLM 输出后做 hallucination/inconsistency 检查 | 新增 trace-first investigation mode 和 output grounding validator |
| `jordigilh/kubernaut` | Go AIOps 自动修复平台 | Alert/Event ingestion、dedup fingerprint、多阶段 triage、LLM investigation、workflow catalog、human approval、外部协作协议、effectiveness scoring、shadow LLM alignment fail-closed | 借鉴 evidence grounding、效果验证和 shadow review；Coroot 侧不内置页面执行 workflow |
| `Mustafa3946/llm-rca-assistant` | Local-first RAG RCA 原型 | 日志预处理、feature store、embedding、FAISS 检索、local LLM、隐私优先 | 新增历史事故/日志模式 RAG，可选本地模型和隐私模式 |

#### 2.6.3 研究论文补充

| 来源 | 可借鉴结论 |
|---|---|
| RCACopilot | 使用 alert type 匹配 incident handler，自动收集关键诊断信息，预测 root cause category 并生成解释叙述；适合引入“场景处理器/handler”机制 |
| SynergyRCA | Kubernetes 场景下可结合 StateGraph、MetaGraph 和专家提示做 RAG，减少幻觉并提高定位精度；适合引入时空状态图 |
| OpenRCA benchmark | LLM 需要理解 KPI time series、dependency trace graphs、semi-structured logs；评测必须要求模型输出根因发生时间、组件、原因 |

### 2.7 groundcover / Metoro / Pixie 对比结论

| 产品 | 与 Coroot 的重叠 | 领先点或差异 | PRD 借鉴 |
|---|---|---|---|
| groundcover | eBPF、Kubernetes、APM、logs、metrics、traces、AI/Agent investigation | 强调 BYOC、数据留在用户云内、full-fidelity telemetry、Agent Mode、RUM/AI observability、跨 Slack/Jira/coding agent workflow | 强化私有化部署、数据不出域、Agentic 调查轨迹、外部 workflow connector 和成本可观测 |
| Metoro | eBPF、Kubernetes APM、logs、metrics、traces、profiling、AI RCA | 强调 AI SRE、deployment verification、generated fixes、外部 uptime/status pages、Kubernetes resource time travel；其页面声称 server-side RED/TLS 覆盖更完整 | 增加 deployment verification、修复建议到 PR/工单的闭环、K8s resource timeline、外部 uptime/status page 作为 P1/P2 能力 |
| Pixie | 开源、Kubernetes-native、eBPF 自动采集、service map、pod state、flame graph、full-body request、脚本化调试 | 更偏开发者实时 debug；数据本地存储/查询在集群内；PxL 脚本和 CLI 可把诊断过程代码化 | 引入只读调查工具/脚本化 RCA step、短期高保真 in-cluster evidence、可复用诊断脚本库 |
| Coroot 当前定位 | 开源友好、自托管、eBPF + OTel、SLO/Incident/RCA、ClickHouse/Prometheus、AI RCA | 优势是开源、自建、低门槛、与 Kubernetes/服务图/日志模式/SLO 紧耦合；短板是 AI workflow、deployment verification、external uptime/status、agentic remediation 还需增强 | L1 对齐官方 AI RCA；L2 补齐竞品的 Agentic、Remediation、Benchmark、私有化和 workflow 闭环 |

二开方向：

- 不能只追求“会生成 RCA 文本”，必须提供 grounding、trajectory、benchmark、自动修复建议和 effectiveness verification。
- 私有化能力要对标 groundcover 的数据控制叙事：敏感 evidence 默认保留在本地，只发送裁剪 findings，支持 OpenAI-compatible 和本地模型。
- AI SRE 能力要对标 Metoro：把 RCA 从报告升级成“检测 -> 解释 -> 建议 -> 人工确认/外部工单/PR -> 效果验证”，Coroot Incident 详情页不内置一键执行 workflow。
- 调查体验要吸收 Pixie：保留可脚本化、可回放的只读调查步骤，方便 SRE 把高频故障沉淀成标准 RCA handler。

## 3. 产品目标

### 3.1 总目标

在当前 Community 自建版本上补齐 **内置 RCA + AI RCA** 两层能力，使体验接近官方 demo，并具备生产事故自动化、审计和修复闭环能力：

- 内置 RCA：未配置 LLM 时也能生成 evidence、候选根因、传播图、widgets、置信度和 missing evidence。
- AI RCA：配置 Provider 后，基于内置 RCA findings 生成官方风格的短摘要、根因分析、详细说明和修复建议。
- 产品闭环：Settings -> AI 配置、Incident 手动/自动 RCA、列表/通知摘要、失败可重试、结果可审计。

### 3.2 设计原则

- 不把全部原始遥测数据直接丢给 LLM。
- 内置 RCA 不依赖 LLM，必须先完成确定性证据抽取、候选根因排序和可视化证据组织。
- AI RCA 只能消费内置 RCA 的 findings、evidence refs、widgets 和候选评分，不直接分析无限制 raw telemetry。
- LLM 负责把已裁剪证据总结成清晰、可执行的 RCA 报告。
- 所有发给 LLM 的上下文必须可审计、可裁剪、可脱敏。
- Provider 层可扩展，不把业务逻辑绑定到某个模型厂商。

### 3.3 目标模型兼容要求

模型支持范围以官方 AI 配置体验为基础，并按本次二开要求将 OpenAI 默认模型升级到 GPT-5.5：

| Provider | 目标模型/能力 | UI 配置项 | 二开要求 |
|---|---|---|---|
| Anthropic | Claude Opus 4.6，官方推荐 | API Key | 必须内置默认模型 `claude-opus-4-6`，普通 UI 不要求用户填写模型名 |
| OpenAI | GPT-5.5 | API Key | 必须内置默认模型 `gpt-5.5`，普通 UI 不要求用户填写模型名 |
| OpenAI-compatible API | 兼容 OpenAI API 的模型，例如 DeepSeek、Google Gemini | Base URL、API Key、Model | 必须允许用户填写 provider base URL 和模型名 |

备注：官方配置文档当前 OpenAI 示例为 GPT-5.2；本项目按已确认的二开要求使用 `gpt-5.5`，并通过 `DefaultOpenAIModel` 集中常量保持可升级。

实现要求：

- Anthropic 和 OpenAI 的默认模型必须使用代码常量集中定义，便于后续跟随官方升级。
- Settings -> AI 的普通配置体验与官方一致：Anthropic/OpenAI 只填 API Key，OpenAI-compatible 需要填 Base URL、API Key、Model。
- 可通过环境变量或高级配置覆盖 Anthropic/OpenAI 模型名，但默认 UI 不暴露，避免偏离官方体验。
- RCA 任务审计记录必须保存实际使用的 provider 和 model。
- Provider 调用层必须记录模型不支持、额度不足、认证失败、上下文超限等错误类别。

### 3.4 能力分层

#### L0：内置 RCA 基础能力

必须先实现不依赖 LLM 的本地 RCA 引擎：

- Incident 页面可以手动触发 RCA，新事故可以自动进入 RCA 队列。
- 后端基于 SLO、依赖图、指标、日志模式、trace、Kubernetes event、deployment 做 evidence extraction。
- 生成候选根因 Top N、deterministic score、confidence、evidence refs、missing evidence。
- 生成 propagation map 和 evidence widgets。
- AI 未配置、Provider 失败或模型超时时，仍可展示内置 RCA 的 evidence report 和候选根因，不退回空白状态。
- 内置 RCA 结果必须持久化并可回放，作为 AI RCA、benchmark 和人工审计的共同输入。

#### L1：AI RCA 官方同等能力

必须先实现官方 AI RCA 的核心体验闭环：

- AI 设置页支持目标模型矩阵和 test connection。
- AI RCA 基于 L0 内置 RCA findings 生成，不绕过内置 RCA 引擎。
- LLM 只接收已筛选的 findings，不接收无限制原始遥测数据。
- RCA 输出包含短摘要、根因、详细分析、立即修复、传播图和证据 widgets。
- 生成结果能支撑 Incident List、Incident Detail、Notification 三处展示。
- 官方 demo/benchmark fixture 至少覆盖 NetworkChaos、错误部署导致数据库查询放大、CronJob 节点 CPU 饥饿、recommendation memory leak 四类场景。

#### L2：优于官方的增强能力

在 L1 稳定后，二开版本应补充官方 demo 未明显暴露、但生产环境更需要的能力：

- RCA 轨迹可回放：保存每一步 evidence query、候选根因、评分、模型输入摘要和模型输出。
- 根因评分透明：输出 deterministic score、confidence、evidence coverage、missing evidence、hallucination risk。
- 历史知识增强：基于历史 incident、修复动作和结果做 RAG 检索，但只能作为补充证据，不能覆盖实时 evidence。
- 双层防幻觉：规则校验 + 可选 shadow LLM grounding review，发现编造资源名或越权修复建议时 fail closed。
- 修复建议：把 immediate fixes 升级为算法自动输出的 remediation recommendations，展示风险、依据和验证方式；高风险动作只标记 review required，不在 Incident 详情页提供执行流程。
- 私有化优先：OpenAI-compatible 和本地模型部署路径应完整可用，满足内网/合规场景。

## 4. 范围

### 4.1 In Scope

| 模块 | 范围 |
|---|---|
| 内置 RCA 引擎 | Evidence Collector、Signal Extractor、Hypothesis Builder、deterministic scoring、missing evidence、propagation map、widgets |
| AI Provider | Anthropic Claude Opus 4.6、OpenAI GPT-5.5、OpenAI-compatible API |
| AI 设置 | Settings -> AI 页面、`/api/ai` GET/POST/test、配置保存、校验、脱敏展示 |
| RCA 任务 | 手动 RCA、自动 RCA、内置 RCA 状态、AI RCA 状态、重试、超时、并发控制 |
| Evidence | SLO、指标、依赖图、deployment、Kubernetes events、error/slow traces、日志模式 |
| RCA 输出 | `short_summary`、`root_cause`、`detailed_root_cause_analysis`、`immediate_fixes`、`propagation_map`、`widgets` |
| 展示与通知 | Incident Detail、Incident List、通知系统 RCA summary/remediation |
| P1 增强 | deterministic scoring、historical RAG、agentic trajectory、grounding/shadow review、remediation recommendations、evaluation harness |

### 4.2 Out of Scope

- 不实现完整官方 Enterprise 授权系统。
- 不承诺 100% 复刻官方闭源 ML/RCA 算法。
- 不实现模型训练。
- 不把 Coroot Cloud 作为必需依赖。
- 不在第一阶段实现复杂 Anomalies 独立产品线。

## 5. 用户角色

| 角色 | 诉求 |
|---|---|
| 平台管理员 | 配置 AI Provider、控制自动 RCA、查看成本与失败原因 |
| SRE/运维 | 事故发生时快速看到根因和修复建议 |
| 研发负责人 | 从事故列表快速判断影响范围和责任服务 |
| 安全/合规人员 | 确认发给 LLM 的数据范围、脱敏策略和审计记录 |

## 6. 用户故事

| 用户故事 | 关键验收 |
|---|---|
| 平台管理员在 Settings -> AI 配置 Anthropic、OpenAI 或 OpenAI-compatible Provider | Community 构建中 AI 设置页可用；必填校验正确；API Key 脱敏；test connection 可返回明确结果 |
| SRE 在 Incident 页面手动触发内置 RCA | 即使 AI Provider 未配置，也能看到候选根因、关键证据、传播图、widgets 和 missing evidence |
| SRE 在 Incident 页面手动触发 AI RCA | 状态从 `In progress` 到 `Done/Failed` 可见；成功后展示 Root Cause、Detailed RCA、Immediate Fixes |
| 平台管理员开启新事故自动 RCA | 新 incident 自动入队；同一 incident 不重复并发；内置 RCA 不阻塞 watcher；AI RCA 失败可重试 |
| 值班人员在通知中看到 RCA 摘要 | RCA 成功后通知包含 `rca_summary`；未生成 RCA 时通知兼容旧 payload |

## 7. 功能需求

### 7.1 AI 设置

新增/完善后端设置模型：

```go
type AISettings struct {
    Provider          string
    Anthropic         AnthropicSettings
    OpenAI            OpenAISettings
    OpenAICompatible  OpenAICompatibleSettings
    IncidentsAutoRCA  bool
    Readonly          bool
}
```

建议 settings 结构：

```go
const (
    DefaultAnthropicModel = "claude-opus-4-6"
    DefaultOpenAIModel    = "gpt-5.5"
)

type AnthropicSettings struct {
    APIKey string
    Model  string // 默认 DefaultAnthropicModel；普通 UI 不暴露
}

type OpenAISettings struct {
    APIKey string
    Model  string // 默认 DefaultOpenAIModel；普通 UI 不暴露
}

type OpenAICompatibleSettings struct {
    BaseURL string
    APIKey  string
    Model   string
}
```

Provider 取值：

- `""`
- `anthropic`
- `openai`
- `openai_compatible`

配置来源：

- UI 保存到 DB setting。
- 可选支持环境变量只读配置。

建议环境变量：

- `AI_PROVIDER`
- `AI_ANTHROPIC_API_KEY`
- `AI_ANTHROPIC_MODEL`
- `AI_OPENAI_API_KEY`
- `AI_OPENAI_MODEL`
- `AI_OPENAI_COMPATIBLE_BASE_URL`
- `AI_OPENAI_COMPATIBLE_API_KEY`
- `AI_OPENAI_COMPATIBLE_MODEL`
- `AI_INCIDENTS_AUTO_RCA`

### 7.2 Provider 抽象

新增 `ai` 包：

```go
type Provider interface {
    Name() string
    Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
    Validate(ctx context.Context) error
}
```

实现：

- `AnthropicProvider`
- `OpenAIProvider`
- `OpenAICompatibleProvider`

要求：

- Provider 必须默认覆盖目标模型矩阵：Anthropic `claude-opus-4-6`、OpenAI `gpt-5.5`、OpenAI-compatible 用户自定义 model。
- 统一超时。
- 统一错误结构。
- 统一 token/上下文大小限制。
- 支持结构化 JSON 输出。
- 支持 mock provider 进行测试。

### 7.3 RCA Pipeline

新增 `rca` 或 `ai/rca` 服务层，分成内置 RCA 基础路径和 AI RCA 增强路径：

```text
Incident / Anomaly
  -> Time Context
  -> Evidence Collector
  -> Signal Extractor
  -> Hypothesis Builder
  -> Deterministic Scoring
  -> Built-in RCA Result
  -> DB Update
  -> UI Built-in Evidence Report
  -> [AI enabled]
      -> Prompt Builder
      -> LLM Provider
      -> Response Validator
      -> AI RCA Result
      -> DB Update
  -> model.RCA
  -> UI / Notification
```

内置 RCA 是必经路径；AI RCA 是基于内置 RCA result 的可选增强。Provider 未配置、额度不足、模型超时或模型输出非法时，不应丢失内置 RCA 结果。

#### 7.3.1 Evidence Collector

复用当前 `api/rca.go` 的上下文收集逻辑，输出内部 `RCAEvidence`：

- application id/name/category
- incident opened/resolved/duration
- SLO objective/compliance/burn rates
- metrics window
- deployments
- Kubernetes events
- error trace
- slow trace
- relevant log patterns
- direct upstream/downstream dependencies

#### 7.3.2 Signal Extractor

从原始 evidence 中生成可控上下文：

- Top N 异常指标
- Top N 依赖路径
- Top N trace spans
- Top N K8s events
- Top N log patterns
- 最近部署变更
- Top N 相关 widgets，用于支撑 RCA 详情页展示

默认限制：

- traces：最多 3 条
- k8s events：最多 50 条
- log patterns：最多 20 条
- metrics series：只传聚合摘要，不传完整长序列
- rca evidence widgets：目标 8 到 40 个，默认上限 40 个

必须优先抽取的信号：

| 信号类型 | 示例 | 用途 |
|---|---|---|
| SLI | latency p95/p99、errors per second、burn rate | 判断事故影响面和严重度 |
| 服务依赖 | front-end -> catalog -> db-main | 构造 impact chain 和 propagation map |
| Trace | error trace、slow trace、关键 span error | 证明错误传播路径 |
| Deployment | image tag、rollout 时间、deployment name | 识别变更引入问题 |
| Kubernetes events | OOMKilled、BackOff、Unhealthy、FailedScheduling、Chaos 事件 | 识别平台层异常 |
| Node pressure | CPU delay、CPU throttling、CPU consumers | 识别节点资源竞争 |
| DB 指标 | query calls、query total time、locked queries、requests by client | 识别数据库瓶颈 |
| Network 指标 | retransmissions、connection time、service link latency | 识别网络延迟/丢包/Chaos |

#### 7.3.3 Hypothesis Builder

先做非 LLM 排序，生成候选根因：

- 上游依赖延迟/错误升高
- 本服务 CPU/内存/GC/重启异常
- 近期部署或 rollout
- 数据库/缓存依赖异常
- Kubernetes 调度/探针/限流/OOM 事件
- 网络或 DNS 异常
- Chaos 工具或故障注入导致的网络/资源异常
- CronJob/Job/批处理任务挤占节点资源
- 高成本 SQL 或请求放大导致数据库 CPU/IO 饱和
- 应用内存泄漏导致 OOMKilled、restart loop、服务不可用和上游连接失败

输出：

- hypothesis id
- suspected service/component
- confidence
- evidence list
- impacted path

内置场景模板：

| 模板 | 触发证据 |
|---|---|
| `network_chaos_delay` | NetworkChaos/Chaos Mesh 资源、TCP retransmission、连接耗时、跨服务 timeout |
| `bad_deployment_db_query_amplification` | 新 deployment、query calls/total time 激增、DB CPU/CPU delay、请求路径指向新版本 |
| `cronjob_node_cpu_starvation` | CronJob/Job 运行、node CPU consumers 异常、同节点多个服务 CPU delay/throttling |
| `database_bottleneck` | DB latency、locked queries、query total time、requests by client 异常 |
| `resource_exhaustion` | OOMKilled、memory、CPU throttling、restart、GC pause |
| `recommendation_memory_leak` | recommendation memory 持续增长、OOMKilled、container restart、ECONNREFUSED/timeout、frontend-proxy latency/error 升高 |

#### 7.3.4 Prompt Builder

Prompt 必须要求模型输出 JSON：

```json
{
  "short_summary": "...",
  "root_cause": "...",
  "detailed_root_cause_analysis": "...",
  "immediate_fixes": "...",
  "confidence": "low|medium|high",
  "missing_evidence": ["..."]
}
```

要求：

- 不允许模型编造未在 evidence 中出现的服务、命令、namespace。
- 低置信度时必须说明缺失证据。
- 修复建议必须分为立即止血和后续治理。
- Kubernetes 命令只有在 evidence 中出现明确 namespace/name 时才生成。
- `short_summary` 必须是一句话，包含根因触发因素、根因组件和业务影响，目标长度 80 到 180 字符。
- `root_cause` 必须直给结论，目标 400 到 700 字符。
- `detailed_root_cause_analysis` 必须是 Markdown，目标 1500 到 3000 字符。
- `immediate_fixes` 必须短小可执行，目标 230 到 550 字符。
- `detailed_root_cause_analysis` 建议包含 `Incident Overview`、`What happened`、`Impact Chain`、`Evidence`、`Conclusion` 等小节。
- 如果生成命令，必须使用 Markdown 代码块，并在命令前后说明验证方式。

#### 7.3.5 RCA Response Validator

LLM 返回后必须做结构化校验：

- 必须能解析为 JSON。
- 必须包含 `short_summary`、`root_cause`、`detailed_root_cause_analysis`、`immediate_fixes`。
- 字段长度超出预算时进行裁剪或二次摘要。
- 检查服务名、namespace、deployment、job、chaos 资源名是否存在于 evidence。
- 检查 `kubectl` 命令是否引用真实资源名。
- 检查没有把缺失证据写成确定事实。
- 校验失败时最多重试一次，仍失败则 RCA 状态为 `Failed`，错误类型为 `invalid_model_output`。

#### 7.3.6 Propagation Map 与 Widgets

二开版本不能只保存 AI 文本，还要生成与官方类似的可视化证据：

- `propagation_map.applications` 应包含根因服务、受影响服务、关键上下游依赖。
- 每个 application/link 应带 status 和 issues。
- incident 详情保留 2 个基础 SLI widgets：Latency 和 Errors。
- RCA widgets 目标 8 到 40 个，优先展示与根因相关的图表。
- widgets 排序应从用户影响到根因证据：
  1. SLI latency/errors
  2. 受影响服务依赖 latency/errors
  3. 根因组件资源指标
  4. DB/network/trace/log/k8s event 证据

### 7.4 RCA 任务系统

新增 DB 表：

```sql
CREATE TABLE IF NOT EXISTS rca_job (
    project_id TEXT NOT NULL,
    incident_key TEXT NOT NULL,
    application_id TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    attempts INT NOT NULL DEFAULT 0,
    created_at INT NOT NULL,
    updated_at INT NOT NULL,
    started_at INT NOT NULL DEFAULT 0,
    finished_at INT NOT NULL DEFAULT 0,
    PRIMARY KEY (project_id, incident_key)
);
```

状态：

- `queued`
- `running`
- `succeeded`
- `failed`
- `cancelled`

并发控制：

- 默认全局并发：`1`
- 可配置：`AI_RCA_WORKERS`
- 单任务超时：默认 `5m`

### 7.5 API

#### `GET /api/ai`

返回：

```json
{
  "provider": "openai_compatible",
  "readonly": false,
  "incidents_auto_rca": true,
  "anthropic": {
    "api_key": "********",
    "model": "claude-opus-4-6"
  },
  "openai": {
    "api_key": "********",
    "model": "gpt-5.5"
  },
  "openai_compatible": {
    "base_url": "https://api.example.com/v1",
    "api_key": "********",
    "model": "deepseek-chat"
  }
}
```

#### `POST /api/ai`

保存配置并校验 provider。

#### `POST /api/ai/test`

测试连接，不保存或可选保存后测试。

#### `POST /api/project/{project}/incident/{key}/rca`

手动创建/重跑 RCA 任务。

#### `GET /api/project/{project}/incident/{key}/rca/job`

查询任务状态。

兼容现有：

- 保留当前 `GET /api/project/{project}/app/{app}/rca`。
- 旧 UI 仍可通过现有接口触发分析。

### 7.6 Deterministic Root Cause Scoring Engine

为了避免 RCA 变成纯 LLM 文案生成，后端必须在调用模型前完成候选根因评分。

#### 7.6.1 OpenRCA-inspired 内置算法

内置 RCA 第一版采用 OpenRCA 的任务定义和 RCA-agent 思路，但实现为 Coroot 后端内置的安全版本：

- 目标输出从自然语言报告前移为结构化三元组：`root_cause_occurrence_time`、`root_cause_component`、`root_cause_reason`。
- 输入覆盖 OpenRCA 强调的三类核心 telemetry：KPI/SLI time series、dependency trace graph、semi-structured logs，并补充 Coroot 已有的 K8s events、deployments、node/pod evidence、widgets。
- 调查过程采用 bounded retrieval loop：每一步只调用 Coroot 后端注册的只读工具，产生结构化 observation 和 evidence refs。
- 每一步 trajectory 都必须保存，用于 debug、审计、benchmark 和 AI RCA prompt 输入。
- 最终候选必须从 evidence registry 和候选组件/原因枚举中选择，不允许输出不存在的服务、节点、namespace、job、deployment 或 reason。
- 生产实现不执行任意 Python 或用户代码；OpenRCA 中“由模型指挥 Executor 写代码分析 telemetry”的思想，在 Coroot 中映射为固定只读工具和内置聚合函数。

推荐流程：

```text
Incident Window
  -> collect KPI/SLI deltas
  -> collect dependency trace graph deltas
  -> collect log pattern deltas
  -> collect K8s/deployment/node evidence
  -> build candidate time/component/reason triples
  -> run scenario handlers
  -> score candidates
  -> persist trajectory + top candidates
  -> generate built-in RCA evidence report
```

候选三元组结构：

```json
{
  "root_cause_occurrence_time": "2026-07-02T10:15:00Z",
  "root_cause_component": "recommendation",
  "root_cause_reason": "memory_leak_oomkilled",
  "scenario": "recommendation_memory_leak",
  "score": 0.91,
  "confidence": "high",
  "evidence_refs": ["slo:frontend-proxy-errors", "k8s:oomkilled", "trace:econnrefused"],
  "missing_evidence": []
}
```

OpenRCA 思路在 Coroot 中的落地映射：

| OpenRCA 概念 | Coroot 内置 RCA 实现 |
|---|---|
| Natural language RCA task | Incident/SLO anomaly 自动生成 RCA task |
| KPI time series | SLO burn rate、latency/error、resource metrics、DB/network metrics |
| Dependency trace graph | Coroot service map、error/slow traces、upstream/downstream links |
| Semi-structured logs | log pattern、severity、error keyword、pattern hash |
| RCA-agent trajectory | `rca_trajectory`：只读工具调用、输入摘要、输出摘要、evidence refs |
| Final JSON answer | 内置 RCA candidate triples + AI RCA output contract |
| Evaluation scoring points | fixture expected time/component/reason + grounding/unsafe-fix 指标 |

#### 7.6.2 PyRCA-inspired 图评分层

在 OpenRCA 三元组候选之上，内置 RCA 增加 PyRCA 风格的图评分层，用于把异常指标、服务依赖、trace 链路、K8s 资源关系和 domain knowledge 统一成可排序的 evidence graph。

核心思想：

- Stats anomaly detector：对 SLO、服务 RED、资源、DB、network、log pattern 计数等时间序列做异常检测。
- Causal/topology graph：用 Coroot service map、trace parent-child、pod-node、deployment-owner、DB/client、K8s event 关系构建有向图。
- Domain knowledge constraints：把网关/入口服务标为 leaf 候选，node、CronJob、DB、cache、queue、deployment、chaos resource 标为更可能的 root candidate；禁止不合理边，例如用户入口直接导致 node CPU 饱和。
- Random Walk：从受影响 SLI/应用出发，在 evidence graph 上向可能原因方向游走，得到 root candidate 的拓扑相关性分数。
- Bayesian inference：把候选根因和观测异常转成二值/概率 evidence，估计 `P(root_cause | observations)`。
- Hypothesis Testing：对候选组件的 incident window 与 baseline window 做统计检验，复核该候选是否显著异常。

实现要求：

- 第一版不直接把 PyRCA Python runtime 嵌入 Coroot 主进程；优先用 Go 原生实现 PyRCA-inspired scoring，避免运行时复杂度和安全边界扩大。
- 可以保留离线 Python benchmark 脚本，用于对比 PyRCA 原始实现和 Go 内置实现的排序差异。
- 所有图节点必须映射到 Coroot evidence registry，不能出现只存在于算法内部、UI 无法解释的虚拟节点。
- 每个 candidate 必须记录 `pyrca_scores`，包括 random walk、Bayesian、hypothesis testing、domain prior 和 graph path。

建议结构：

```json
{
  "pyrca_scores": {
    "random_walk": 0.84,
    "bayesian": 0.78,
    "hypothesis_testing": 0.91,
    "domain_prior": 0.80,
    "combined": 0.84
  },
  "graph_paths": [
    ["recommendation", "frontend-proxy", "frontend"]
  ],
  "domain_constraints_applied": [
    "frontend-proxy treated as leaf symptom",
    "recommendation allowed as service root candidate"
  ]
}
```

PyRCA 思路在 Coroot 中的落地映射：

| PyRCA 概念 | Coroot 内置 RCA 实现 |
|---|---|
| Metrics dataframe | 统一的 incident window metric matrix，列为 service/node/db/link/log pattern 指标 |
| StatsDetector | baseline window 与 incident window 的异常检测器 |
| Causal graph | service map + trace graph + K8s ownership + node placement + DB/client links |
| Domain knowledge YAML | 代码内置/配置化 domain constraints：root/leaf nodes、required/forbidden links、root cause priors |
| Random Walk RCA | 从异常 SLI/服务在 evidence graph 上反向游走，输出 root candidate rank |
| Bayesian Network RCA | 估计候选根因在当前 observations 下的后验概率 |
| Hypothesis Testing RCA | 用 baseline/incident residual 或分布差异复核候选显著性 |
| Recall@K benchmark | fixture 中评估 Recall@1/3/5 和 graph path 命中率 |

#### 7.6.3 受控检索循环

内置 RCA 可以实现一个不依赖 LLM 的 bounded retrieval loop：

1. 从 incident window 和受影响应用开始。
2. 拉取 SLO/SLI delta，识别最早异常时间点。
3. 沿依赖图向 downstream/upstream 扩展一到三跳。
4. 对每个候选组件收集 metrics、logs、traces、K8s events、deployments。
5. 运行 scenario handlers，生成候选三元组。
6. 运行 PyRCA-inspired 图评分层。
7. 按 7.6.5 的 scoring formula 排序。
8. 输出 Top N 候选和 missing evidence。

循环限制：

- 默认最大扩展深度：`3` 跳。
- 默认最大候选组件：`20` 个。
- 默认最大候选三元组：`10` 个。
- 默认单 incident 内置 RCA 超时：`60s`。
- 所有工具必须只读、可审计、可限流。

#### 7.6.4 输入与输出

输入：

- Incident 时间窗、opened/resolved/duration。
- 受影响应用和 SLO 退化类型。
- 依赖图上下游拓扑。
- 指标异常摘要。
- deployment/change events。
- Kubernetes events。
- trace/log pattern 证据。
- 历史相似 incident 命中结果。

输出：

```json
{
  "candidates": [
    {
      "id": "h-001",
      "root_cause_occurrence_time": "2026-07-02T10:15:00Z",
      "component": "analytics-updater",
      "component_type": "cronjob",
      "root_cause_reason": "node_cpu_starvation",
      "scenario": "cronjob_node_cpu_starvation",
      "pyrca_scores": {
        "random_walk": 0.82,
        "bayesian": 0.76,
        "hypothesis_testing": 0.88,
        "combined": 0.82
      },
      "score": 0.91,
      "confidence": "high",
      "reason_codes": [
        "same_time_window",
        "node_cpu_saturation",
        "dependency_propagation_match"
      ],
      "evidence_refs": ["metric:node3_cpu_delay", "event:job_started", "widget:WIDGET-9"]
    }
  ]
}
```

#### 7.6.5 评分维度

| 维度 | 含义 |
|---|---|
| Temporal fit | 候选根因发生时间是否领先或重叠事故开始时间 |
| Topology distance | 候选组件到受影响应用的依赖距离 |
| Anomaly strength | 指标/日志/trace 异常强度 |
| Change evidence | 是否存在 deployment、job、config、chaos、K8s event |
| Propagation consistency | 异常是否沿依赖路径传播 |
| Historical similarity | 历史 RCA 中是否出现过相似 pattern |

建议公式：

```text
deterministic_evidence_score =
  0.20 * temporal_fit
+ 0.20 * topology_fit
+ 0.20 * anomaly_strength
+ 0.15 * event_or_change_evidence
+ 0.10 * trace_log_support
+ 0.10 * propagation_consistency
+ 0.05 * historical_similarity

pyrca_graph_score =
  0.35 * random_walk
+ 0.30 * bayesian
+ 0.25 * hypothesis_testing
+ 0.10 * domain_prior

final_score =
  0.50 * deterministic_evidence_score
+ 0.30 * pyrca_graph_score
+ 0.15 * scenario_handler_score
+ 0.05 * historical_similarity
```

权重总和允许按场景归一化。没有历史样本时 `historical_similarity` 可置 0，并把剩余权重归一化。

验收：

- 每条成功 RCA 必须保存 `candidates` 和最终选中原因。
- 每个 candidate 至少包含 root cause occurrence time、component、reason 三类字段中的 component 和 reason；能推断时间时必须输出 occurrence time。
- 每个 candidate 必须包含 `pyrca_scores.combined`；缺少足够图/指标数据时必须说明 PyRCA scoring unavailable 的原因。
- UI 可以在 debug/expand 区域展示 Top 3 candidate。
- LLM 不允许选择未出现在 `candidates` 或 evidence 中的组件作为确定根因。
- Fixture regression 必须分别评估 component accuracy、reason accuracy、time within tolerance。

### 7.7 Historical RCA Knowledge Base / RAG

新增历史 RCA 知识库，用于复用过去 incident 的诊断经验。

#### 数据来源

- 成功 RCA 的结构化输出。
- 人工编辑后的 root cause 和 fix。
- remediation recommendation 与效果验证结果。
- 事故恢复时间、复发情况、效果验证结果。

#### 建议结构

```sql
CREATE TABLE IF NOT EXISTS rca_case (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    incident_key TEXT NOT NULL,
    signature_hash TEXT NOT NULL,
    scenario TEXT NOT NULL,
    root_cause_component TEXT NOT NULL,
    evidence_fingerprint TEXT NOT NULL,
    fix_summary TEXT NOT NULL,
    outcome TEXT NOT NULL,
    created_at INT NOT NULL
);
```

可选向量索引字段：

- scenario tags
- application names
- dependency path
- log pattern hash
- Kubernetes reason
- metric anomaly tags
- fix/result summary embedding

使用边界：

- RAG 结果只能作为 `historical_context`，不能作为事实证据。
- RAG 命中必须显示相似度和历史 incident key。
- 当实时 evidence 与历史 case 冲突时，以实时 evidence 为准。
- 默认不把原始日志全文写入知识库，只保存 pattern、摘要和脱敏字段。

### 7.8 Agentic Investigation and Trajectory

借鉴 OpenRCA、Kubernaut 和 agentic observability 项目的做法，提供可回放的调查轨迹，但工具调用必须限制在 Coroot 后端定义的只读函数内。

#### 只读调查工具

- `get_incident_context`
- `get_slo_impact`
- `get_applications_overview`
- `get_service_health`
- `get_dependency_neighbors`
- `get_metric_anomalies`
- `get_nodes_overview`
- `get_error_traces`
- `get_slow_traces`
- `get_log_patterns`
- `get_kubernetes_events`
- `get_deployments`
- `get_costs_overview`
- `get_risks_overview`
- `get_related_rca_cases`

#### 轨迹记录

```json
{
  "steps": [
    {
      "step": 1,
      "tool": "get_metric_anomalies",
      "input_summary": "front-end, incident window",
      "output_summary": "node3 cpu delay and throttling spike",
      "evidence_refs": ["metric:node3_cpu_delay"],
      "duration_ms": 184
    }
  ]
}
```

要求：

- 默认走 deterministic pipeline；agentic mode 作为增强或 debug 模式。
- 每个 step 必须有超时、最大返回量和敏感字段脱敏。
- 轨迹保存用于审计、回放、benchmark，不直接暴露 API Key 或原始 prompt。
- 模型最多执行固定步数，默认 8 步；超过后必须产出 best-effort 结果或失败。

### 7.9 Grounding, Hallucination Guard, and Shadow Review

RCA 生成后必须经过 grounding 校验，防止模型编造组件、namespace、命令或不安全修复动作。

#### 规则校验

- 所有服务名、namespace、deployment、job、pod、node 必须能在 evidence registry 中找到。
- 所有图表引用必须对应真实 widget id。
- 所有 `kubectl` 命令必须引用真实 namespace/name。
- 如果 evidence 中没有权限、资源名或变更窗口，不允许生成破坏性命令。
- `confidence=high` 必须至少满足：有拓扑证据、时间证据、根因组件证据三类中的两类。

#### Shadow Review

可选启用第二模型或轻量规则模型进行 shadow review：

- 输入：RCA 输出 + evidence registry 摘要。
- 输出：`grounded|suspicious|unsafe`。
- `suspicious` 时降低 confidence 并显示 missing evidence。
- `unsafe` 时 RCA 状态进入 `needs_human_review`，不推送自动修复。

### 7.10 Remediation Recommendations and Effectiveness Verification

官方 demo 的 immediate fixes 偏报告型；二开版本应在 RCA 生成后自动输出只读修复建议，直接展示在 RCA 详情中，不要求用户额外启动流程。

#### Recommendation Catalog

内置建议类型：

- 查看 rollout history。
- 查看 CronJob/Job 状态。
- 查看 K8s event。
- 扩容建议预检查。
- 回滚建议预检查。
- 暂停 CronJob 建议预检查。
- 删除/暂停 Chaos 资源建议预检查。

高风险动作必须标记 `review required`，但不在 Incident 详情页内提供一键执行：

- rollout undo
- scale deployment
- patch resource requests/limits
- suspend CronJob
- delete Chaos resource

#### 效果验证

输出建议时必须同时给出验证口径。执行或人工确认修复后，系统应在恢复窗口内评估：

- SLO burn rate 是否下降。
- error rate/latency 是否恢复。
- 根因指标是否恢复。
- 下游传播链路是否恢复。
- 相同 incident 是否复发。

输出字段：

- `title`
- `description`
- `risk`
- `requires_approval`
- `evidence_refs`
- `verification`
- `status=recommended`

### 7.11 Evaluation Harness

为了验证“同等或优于官方”，必须建立可重复运行的 RCA benchmark。

Harness 职责：

- 读取 `12.1` 和 `13` 定义的 fixture。
- 分别运行内置 RCA、AI RCA、grounding validator 和 remediation safety check。
- 输出候选根因排序、命中率、证据覆盖、graph path、latency、token/cost 和失败样本。
- 保存每次变更的 benchmark 报告，便于比较 Prompt、Scoring、Provider 或 Evidence Collector 的效果。

质量指标与发布门禁统一维护在 `12.2`，避免同一阈值在多处漂移。

## 8. UI 需求

### 8.1 Settings -> AI

保留当前 UI 布局，解除 Community 禁用逻辑。

新增：

- 自动调查开关：`Investigate incidents automatically`
- Test connection 按钮
- 当前 Provider 状态
- API Key 脱敏显示
- 只读配置提示

### 8.2 Incident Detail

当 RCA 不存在：

- 始终显示 `Run built-in RCA`，用于生成本地 evidence report。
- AI 已配置：同时显示 `Investigate with AI` 或 `Run AI RCA`。
- AI 未配置：在 AI RCA 区域显示 `Enable an AI integration`，但不影响内置 RCA 触发。

当 RCA 运行中：

- 显示 `In progress`
- 支持刷新状态

当 RCA 成功：

- Root Cause
- Immediate Fixes
- Show more details
- Propagation Map
- Relevant charts

当 RCA 失败：

- 显示失败原因
- 支持重试

### 8.3 Incidents List

- RCA 成功后，Description 优先使用 `short_summary`。
- Root Cause 列显示状态：
  - Done
  - In progress
  - AI disabled
  - Failed
  - Out of credits / Provider error

## 9. 安全与合规

### 9.1 Secret 保护

- API Key 不写入日志。
- GET 返回必须脱敏。
- 错误信息不得包含完整 key。
- 支持环境变量只读模式。

### 9.2 数据脱敏

发送给 LLM 前默认脱敏：

- token/password/secret/key
- Authorization header
- Cookie
- email 可选脱敏
- IP 地址可配置是否脱敏

### 9.3 审计

记录：

- 谁触发 RCA
- incident key
- provider
- model
- input token 估算
- output token 估算
- latency
- status
- error category

不记录：

- API Key
- 完整原始 trace payload
- 完整日志明文

## 10. 非功能需求

| 项目 | 要求 |
|---|---|
| RCA 超时 | 默认 5 分钟 |
| 自动 RCA 并发 | 默认 1 |
| 手动 RCA 并发 | 默认 2 |
| 失败重试 | 默认 2 次，指数退避 |
| Provider 超时 | 默认 120 秒 |
| Prompt 大小 | 默认不超过模型上下文的 60% |
| UI 刷新 | 5 秒轮询任务状态或复用现有刷新机制 |

## 11. 迭代计划

按“先可用、再对齐官方、再生产化、最后增强”的顺序推进。

| 优先级 | 目标 | 开发内容 | 依赖 | 验收标准 |
|---|---|---|---|---|
| P0-1 | 解锁 Community AI 配置 | Settings -> AI 解除禁用；实现 `AISettings`、`/api/ai` GET/POST/test；支持 Anthropic、OpenAI GPT-5.5、OpenAI-compatible；API Key 脱敏与只读环境变量 | 现有 Settings/API 框架 | 三类 Provider 可配置/test；错误分类清晰；API Key 不出现在 GET/log/error |
| P0-2 | 内置 RCA 最小闭环 | Evidence Collector、Signal Extractor、Hypothesis Builder；输出 Top N candidate、missing evidence、基础 propagation map、8 到 40 个 widgets；写入 incident RCA 字段 | 现有 `api/rca.go`、incident/model.RCA | AI 未配置时也能手动生成 RCA evidence report；Incident Detail 可展示状态、根因候选和证据 |
| P0-3 | OpenRCA/PyRCA 核心评分 | OpenRCA-inspired time/component/reason 三元组；PyRCA-inspired graph score；deterministic scoring formula；Top 3 candidate debug 展示 | P0-2 evidence registry | candidate 包含 occurrence time、component、reason、`pyrca_scores.combined`、score、confidence、evidence refs |
| P1-1 | AI RCA 官方体验对齐 | Prompt Builder、LLM Provider 调用、JSON response validator、字段长度控制、grounding 基础校验；生成 `short_summary`、`root_cause`、`detailed_root_cause_analysis`、`immediate_fixes` | P0-1、P0-2、P0-3 | AI 可用时生成官方结构化 RCA；不编造 evidence 外的服务/namespace/命令；失败不覆盖内置 RCA |
| P1-2 | 自动 RCA 任务系统 | `rca_job` 表、后台 worker、自动 RCA 开关、重试、超时、并发、任务状态 API；watcher 只入队不阻塞 | P0 内置 RCA、P1-1 Provider | 新 incident 自动入队；同一 incident 不重复并发；失败可重试；任务状态可查询 |
| P1-3 | 官方 demo parity | 建立 `network_chaos_delay`、`bad_deployment_db_query_amplification`、`cronjob_node_cpu_starvation`、`recommendation_memory_leak` 场景模板和 fixture | P0/P1 核心链路 | 通过 `12.1` demo parity fixture；成功 RCA 至少 8 个 evidence widgets |
| P2-1 | 安全与审计生产化 | evidence 脱敏、prompt 裁剪、provider/model/token/cost/latency 审计、错误可观测性、API Key 泄露防护 | P1 可用链路 | 审计字段完整；敏感字段不进入 prompt/log；Provider 错误可定位 |
| P2-2 | Benchmark 与质量门禁 | Evaluation Harness、fixture regression、评分报告、CI/手动回归脚本 | P1-3 fixture | 输出 `12.2` 指标报告；Prompt/Scoring/Provider/Evidence Collector 变更后可重复跑回归 |
| P2-3 | Grounding 与 Shadow Review | evidence registry 强校验、widget id 校验、kubectl 命令资源校验、可选 shadow review、unsafe fail-closed | P1-1 validator | hallucinated resource rate 为 0；unsafe fix rate 为 0；高风险建议进入人工审核 |
| P3-1 | Historical RCA / RAG | `rca_case`、历史相似 incident 检索、相似度展示、历史修复结果复用 | P2 审计与脱敏 | 历史命中只作为 `historical_context`；实时 evidence 优先 |
| P3-2 | Agentic Investigation | 只读调查工具、trajectory 保存、step 超时/限流、debug 回放 | P0 evidence 工具、P2 安全策略 | RCA 调查过程可回放；固定步数内产出 best-effort 或失败原因 |
| P3-3 | Remediation Recommendations | recommendation catalog、risk/review 标记、evidence refs、effectiveness verification、外部工单/PR 扩展点 | P2 grounding、安全策略 | RCA 详情自动展示建议；不提供内置执行 workflow；修复后可验证 SLO/根因指标/传播链路是否恢复 |

## 12. 测试计划

| 类型 | 覆盖内容 |
|---|---|
| 单元测试 | Evidence Collector、deterministic scoring、AI settings 校验、API Key 脱敏、Provider request/response、Prompt builder、Evidence redaction、RCA job 状态机 |
| 集成测试 | 手动内置 RCA、`/api/ai` GET/POST/test、AI RCA 触发、RCA 结果写入 DB、Incident 页面读取 RCA |
| E2E 测试 | 未配置 AI 时触发内置 RCA；配置 OpenAI-compatible Provider 后触发 AI RCA；等待 `Done`；校验 Root Cause/Immediate Fixes |
| 回归测试 | AI 未配置、Cloud 集成路径、Incident list 分页、通知系统兼容旧 payload |
| Benchmark | 官方 demo fixture、`z14gocke`、`recommendationCacheFailure`、当前 `notice-center`、合成故障注入 fixture |

### 12.1 官方 demo parity fixture

| Fixture | 期望场景 | 必须命中的输出 |
|---|---|---|
| network-chaos-catalog-db | `network_chaos_delay` | catalog -> db-main 网络延迟，fix 包含删除/暂停 Chaos 资源 |
| catalog-050-db-query | `bad_deployment_db_query_amplification` | catalog 新版本、BrandProducts 查询放大、DB CPU/query load，fix 包含回滚 deployment |
| catalog-050-db-query-centric | `bad_deployment_db_query_amplification` | catalog/db-main 两节点拓扑、26 个 DB-centric widgets、catalog readiness/timeout 影响和简洁 rollback fix |
| analytics-updater-node-cpu | `cronjob_node_cpu_starvation` | analytics-updater CronJob、node CPU 饥饿、受影响服务链路 |
| demo-z14gocke-show-more-details | `cronjob_node_cpu_starvation` | trace dependency chain、node3 CPU saturation、analytics-updater CronJob、cascading impact、resource isolation fix |
| recommendation-cache-failure | `recommendation_memory_leak` | recommendation memory leak、OOMKilled/restarts、ECONNREFUSED/timeout、frontend-proxy latency/error、止血和根治分离 |
| demo-glkfv23y-stateful-dependency | `stateful_dependency_eviction_restart` | failed TCP connections、stateful dependency restarts/eviction、ephemeral-storage evidence、database context widgets、StatefulSet resource patch fix |

### 12.2 质量指标与发布门禁

| 指标 | 目标 |
|---|---|
| 场景分类准确率 | >= 90% |
| Root cause time tolerance | 可推断时间的 fixture 中，误差 <= 1 分钟 |
| Root component Recall@1 | >= 80% |
| Root component Recall@3 | >= 95% |
| Root component Recall@5 | >= 97% |
| Root reason accuracy | >= 85% |
| Graph path hit rate | >= 85% |
| 成功 RCA 必填字段覆盖率 | 100% |
| Evidence grounding rate | >= 98% |
| Hallucinated resource rate | 0 |
| Unsafe fix rate | 0 |
| Median RCA latency | <= 120s |

发布要求：

- P1 发布前必须通过官方 demo parity fixture。
- P2 发布前必须输出 benchmark 报告，包含准确率、Recall@1/3/5、grounding、unsafe fix、latency、token/cost。
- 官方 benchmark fixture 必须记录模型、input/output tokens、estimated cost 和评分结果，便于与 Coroot benchmark 方法对齐。
- Prompt、scoring、provider 默认模型或 evidence collector 修改后必须重新跑 fixture regression。

## 13. Codex RCA 样例：当前 `notice-center` 事故

来源：当前线上 Coroot 页面 `https://coroot.crabxtest.com/p/9ceoplec/incidents?incident=rft0dlbs`

该样例用于本地 fixture，不作为确定 RCA 结论。当前可见信息显示 `notice-center` 同时出现 availability 和 latency SLO 退化：Availability compliance 约 `46.8%`，Latency compliance 约 `77.53%`，1h/5m burn rate 均超过阈值 `14`，页面仍显示 `AI disabled`。

fixture 要求：

- AI RCA 必须先说明这是持续性 SLO 退化，而不是短暂抖动。
- 在缺少 error trace、slow trace、Kubernetes events、deployment、关键日志和依赖同步异常前，不能给出确定根因。
- 生成结果必须包含 `missing_evidence`，并把下一步排查聚焦到 trace、服务资源、Kubernetes events、deployment 和依赖图。
- 如果后续 evidence 指向近期部署、资源耗尽、关键下游或数据库慢查询，RCA 才能生成对应止血建议。

## 14. 验收总标准

功能完成后，当前自建版本必须通过以下发布 gate：

| Gate | 验收标准 |
|---|---|
| Provider 配置 | Settings -> AI 可配置 3.3 的模型矩阵；API Key 脱敏；test connection、只读配置、错误分类可用 |
| 内置 RCA | 未配置 AI 时，Incident 仍可生成 evidence report、Top N candidate、OpenRCA 三元组、PyRCA graph score、propagation map、widgets 和 missing evidence |
| AI RCA | AI 可用时，基于内置 RCA findings 生成官方结构：`short_summary`、`root_cause`、`detailed_root_cause_analysis`、`immediate_fixes`、`propagation_map`、`widgets` |
| 自动化与 UI | 新事故可自动入队；手动重跑可用；Incident Detail/List/Notification 展示 RCA 状态和短摘要；Provider 失败不覆盖内置 RCA 结果 |
| Grounding 与安全 | 所有组件、namespace、deployment、job、node、widget、命令均来自 evidence registry；历史 RAG 只作补充；高风险修复只输出 review required 建议，不在 Coroot 内一键执行 |
| Benchmark | 覆盖官方 demo fixture、`z14gocke`、`recommendationCacheFailure`、当前 `notice-center` 和合成故障；发布前输出 12.2 指标报告 |

## 15. 当前开发状态

更新日期：2026-07-03

| 优先级 | 状态 | 已落地内容 | 剩余说明 |
|---|---|---|---|
| P0-1 | 已完成 | Community AI 配置页解锁；`/api/ai` GET/POST/test；Anthropic、OpenAI GPT-5.5、OpenAI-compatible；API Key 脱敏；环境变量只读配置 | 真实 Provider 连通性取决于用户 API Key 和网络出口 |
| P0-2 | 已完成 | 内置 RCA 输出 `short_summary`、`root_cause`、`detailed_root_cause_analysis`、`immediate_fixes`、propagation map、widgets、missing evidence | Evidence 深度会随 Coroot 当前已采集的 metrics/logs/traces/events 完整度变化 |
| P0-3 | 已完成 | OpenRCA-style time/component/reason candidate；PyRCA-inspired random walk、Bayesian、hypothesis testing、domain prior 和 combined score；Top candidates UI 展示 | 第一版为 Go 原生启发式实现，不嵌入 PyRCA Python runtime |
| P1-1 | 已完成 | AI RCA 基于内置 RCA findings 调用 Provider；JSON 输出校验；基础脱敏；Provider/model/token/latency/validator 审计字段；Provider 失败保留内置 RCA | Shadow LLM review 和强资源名校验保留到 P2 |
| P1-2 | 已完成 | `rca_job` 表；后台 RCA worker；`AI_RCA_WORKERS` 并发配置；自动 RCA 入队；手动 POST 重跑；任务状态 API；watcher 不再同步阻塞 | 当前 worker 为进程内队列，后续可扩展为多实例抢占式 DB worker |
| P1-3 | 已完成 | 已内置 network chaos、bad deployment DB query amplification、cronjob node CPU starvation、recommendation memory leak 等场景识别规则；新增 demo parity fixture 回归测试 | 后续可持续补充更多线上事故 fixture |
| P2-1 | 已完成 | Evidence 文本脱敏、AI 输出裁剪、provider/model/token/latency/validator 审计、grounding 状态、hallucination risk、unsafe fix 标记 | 更强的字段级脱敏策略可按合规要求继续扩展 |
| P2-2 | 已完成 | 新增 `rca/benchmark.go` evaluation harness；覆盖 demo parity fixture、Scenario Accuracy、Recall@1/3、Reason Accuracy、Grounding、Unsafe Fix 指标 | 当前为代码内 fixture harness，后续可接入真实导出的官方 demo JSON |
| P2-3 | 已完成 | 新增 grounding validator：evidence term registry、coverage score、资源名 hallucination 检测、kubectl 高风险动作识别、unsafe fail-closed 标记 | Shadow LLM review 作为可选增强未默认启用 |
| P3-1 | 已完成 | 新增 `rca_case` 表；成功 RCA 自动沉淀 signature/scenario/component/fix；新 RCA 加载相似历史 case 作为 supplemental context | 当前为结构化相似检索，不做向量 embedding |
| P3-2 | 已完成 | RCA trajectory 已持久化并在 Incident 详情展示只读调查步骤 | Agentic LLM 动态工具调用未默认启用，避免扩大安全边界 |
| P3-3 | 已完成 | 新增 remediation recommendation catalog；按场景自动生成止血/治理建议、risk、review required、evidence refs、verification；Incident 详情只读展示 `Recommended Actions` | 对齐官方展示习惯，不再暴露 workflow 按钮 |

### 15.1 2026-07-03 追加生产化补强

| 项目 | 状态 | 落地说明 |
|---|---|---|
| RCA 失败重试 | 已完成 | Worker 对可重试失败默认最多重试 2 次，采用指数退避；application not found、multi-cluster unsupported、metric cache empty 等致命原因不重试 |
| Provider 超时 | 已完成 | LLM completion 调用统一包裹 120 秒超时；HTTP/网络错误归类为 `auth_failed`、`model_not_found`、`rate_limited`、`quota_exceeded`、`context_too_large`、`provider_unavailable`、`timeout` 等 |
| UI 任务轮询 | 已完成 | Incident 手动 RCA 触发后每 5 秒查询 `rca_job` 状态，任务结束后刷新事故详情 |
| Remediation 建议 | 已完成 | RCA 后处理自动生成 `Recommended Actions` 并追加到 `detailed_root_cause_analysis`；Incident 详情直接展示 Action/Risk/Evidence/Verification，不要求额外操作 |
| Benchmark 报告入口 | 已完成 | 新增 `/api/rca/benchmark`，输出 demo parity fixture contract、指标报告和 pass/fail 状态；AI 设置页增加 Benchmark 报告入口 |
| 回归测试 | 已完成 | 新增 Provider 错误分类、RCA retry 判断、remediation 状态机、状态合并、demo parity benchmark report 回归测试 |

### 15.2 2026-07-07 企业版 AI RCA 契约吸收

| 项目 | 状态 | 落地说明 |
|---|---|---|
| 官方请求契约 | 已完成 | 通过授权企业版试用环境和 OpenAI-compatible 脱敏代理确认：Incident AI RCA 使用 Chat Completions、强制 `record_summary` tool call、`max_completion_tokens=8000`，必填 `short_summary`、`root_cause`、`immediate_fixes`、`detailed_root_cause_analysis` |
| OpenAI-compatible parity | 已完成 | 本地 `ai.Provider` 已支持 `tools/tool_choice`，优先解析 `tool_calls[].function.arguments`，OpenAI/GPT-5 系列使用 `max_completion_tokens`，兼容官方结构化输出方式 |
| Prompt parity | 已完成 | 本地 AI RCA system prompt 已吸收官方语义：Coroot 作为生产排障工具、依赖图相关性、profile diff 解读约束、禁止臆造资源/命令/widget |
| Widget grounding | 已完成 | AI 输出后处理会保留合法 `WIDGET-N`，清理 `WIDGET-<ID>`、`WIDGET-N` 占位符和越界 widget 引用，并写入 `missing_evidence`，避免官方试用中观察到的 widget 占位符残留问题 |
| 脱敏抓包工具 | 已完成 | 新增 `hack/ai-redacting-proxy.py` 与文档，可 dry-run 捕获模型请求结构、tool schema、消息长度、hash 和脱敏摘要，不暴露 API key 或 license |

### 15.3 2026-07-07 RCA Grounding 增强

| 项目 | 状态 | 落地说明 |
|---|---|---|
| 资源名防幻觉 | 已完成 | `grounding.hallucinated_resources` 会列出 RCA 文本和修复建议中出现、但不在候选根因/evidence/trajectory/PropagationMap/widgets 中的资源名，例如未证实的 Deployment、NetworkChaos、Service 或 DB 节点 |
| 前端可审计展示 | 已完成 | Incident 详情 Grounding 面板展示 evidence coverage、hallucination risk、issues 和未证实资源，SRE 可直接判断 AI RCA 是否需要人工复核 |
| Benchmark 门槛 | 已完成 | Demo parity benchmark 将 hallucinated resources 纳入 pass/fail，要求官方同类场景 RCA 不能引用 evidence 外资源 |

### 15.4 2026-07-07 AIOps-observability-agent 能力吸收

参考 `dungnotnull/AIOps-observability-agent` 后，本项目只吸收适合内置 RCA 的能力，不引入 Python sidecar、PyTorch、Prophet、FAISS 或额外 LLM 决策链。

| 能力 | 外部项目思路 | 本项目 Go 内置落地 |
|---|---|---|
| Anomaly detector | LSTM autoencoder；无 PyTorch 时用 statistical fallback、z-score、severity threshold | 新增 `rca.BuildAnomalySignals`，从候选根因 score breakdown、anomaly strength、propagation、evidence refs 生成 `rca.anomalies`；detector 标记为 `statistical_red_fallback` |
| SLO predictor | Prophet/N-BEATS；无模型时线性趋势 fallback + breach probability | 新增 `rca.BuildSLOForecasts`，基于 anomaly score、candidate confidence 和 SLO 类型生成 `rca.slo_forecasts`，输出 breach probability、time-to-breach、target、forecast value |
| Runbook generator | LLM 生成 7 段 runbook 并做 section validation | 新增 `rca.BuildRunbook`，完全由 RCA evidence/remediation 生成 7 段结构化 runbook，写入 `rca.runbook`，不依赖 LLM 且不编造资源 |
| UI 展示 | sidecar API 展示 runbooks/SLO/anomalies | Incident 详情新增 `AIOps Anomaly Signals`、`SLO Risk Forecast`、`AIOps Runbook` 三块只读展示 |
| 审计轨迹 | orchestrator pipeline 串联 metrics -> anomaly -> RCA -> SLO -> runbook | RCA `trajectory` 自动追加 `aiops_signal_enrichment`，把生成过程纳入证据链 |
| 安全约束 | sidecar 由外部 LLM/模板生成内容 | 证据不足候选不生成 anomaly/SLO 预测；grounding validator 同时检查 root cause、immediate fixes、remediation 和 runbook 中的资源引用 |

## 16. 参考依据

### 16.1 Coroot 官方资料

本 PRD 的模型矩阵、RCA 方法论和 demo parity 以 Coroot 官方资料为准：

- Coroot AI Configuration：`https://docs.coroot.com/ai/configuration/`
- Coroot AI Overview：`https://docs.coroot.com/ai/overview/`
- Coroot AI Cloud：`https://docs.coroot.com/ai/coroot-cloud/`
- Coroot AI RCA blog：`https://coroot.com/blog/we-built-ai-powered-root-cause-analysis-that-actually-works/`
- Coroot AI RCA anatomy blog：`https://coroot.com/blog/anatomy-of-ai-powered-root-cause-analysis/`
- Coroot AI benchmark：`https://coroot.com/ai-benchmark`
- Coroot benchmark scenario：`https://coroot.com/ai-benchmark/scenarios/recommendationCacheFailure`
- Coroot demo incidents：`https://demo.coroot.com/p/tbuzvelk/incidents`
- Coroot demo incidents API：`https://demo.coroot.com/api/project/tbuzvelk/incidents?limit=5000`
- Coroot demo `z14gocke` incident API：`https://demo.coroot.com/api/project/tbuzvelk/incident/z14gocke`

目标模型矩阵以 `3.3` 为唯一口径；后续如果官方文档升级默认模型，二开版本应通过 `DefaultAnthropicModel`、`DefaultOpenAIModel` 等集中常量同步升级。

### 16.2 GitHub/开源项目参考

以下项目用于提炼工程设计，不直接复制代码：

- Salesforce PyRCA：`https://github.com/salesforce/PyRCA`
- Microsoft OpenRCA：`https://github.com/microsoft/OpenRCA`
- ORCA：`https://github.com/openrca/orca`
- Agentic AI Root Cause Observability：`https://github.com/Ebrahiminegin67/agentic-ai-root-cause-observability`
- Kubernaut：`https://github.com/jordigilh/kubernaut`
- LLM RCA Assistant：`https://github.com/Mustafa3946/llm-rca-assistant`

### 16.3 论文/Benchmark 参考

- OpenRCA paper：`https://openreview.net/forum?id=M4qNIzQYpd`
- PyRCA paper：`https://arxiv.org/abs/2306.11417`
- SynergyRCA：`https://arxiv.org/abs/2506.02490`
- RCACopilot：`https://arxiv.org/abs/2305.15778`

### 16.4 竞品对比参考

- Coroot Kubernetes Observability：`https://coroot.com/kubernetes`
- groundcover：`https://www.groundcover.com/`
- Metoro vs Coroot：`https://metoro.io/metoro-vs-coroot`
- Pixie：`https://px.dev/`
- Pixie Overview：`https://docs.px.dev/about-pixie/what-is-pixie/`
