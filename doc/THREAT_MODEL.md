# TapChat 威胁模型与元数据隐私边界

本文档描述当前 `0.1.x` 架构实际提供的安全属性和明确不提供的属性。它是 README、架构计划和协议文档中“抗审查”“元数据隐私”表述的解释基准。

## 1. 安全目标

- 消息、附件和 MLS group state 的明文只在客户端处理。
- Transport 只保存或转发加密 Envelope、加密 Blob 以及完成路由和授权所需的状态。
- 用户可以选择和控制自己的 Transport，避免由单一 TapChat 中心统一持有所有账号、消息和关系数据。
- Capability、设备签名和 Group manifest 必须 fail-closed；恢复失败、签名失败或权限状态不连续时不得降级运行。

这里的“元数据隐私”是降低中心化聚合和跨群关联能力，不等同于匿名通信，也不保证隐藏单个群的成员关系。

## 2. 当前可见元数据

Cloudflare 参考 Transport 及其账户拥有者可能观察到：

- 请求来源 IP、User-Agent、访问时间、频率、消息大小和 endpoint 路径；
- Inbox、Storage、Group Outbox 的对象数量、游标变化和流量模式；
- 稳定或半稳定的 user、device、group、share endpoint 和 capability 关联；
- Cloudflare 账户、部署区域、账单和运维层面的关联信息。

Group Outbox 为了执行 `group_authorization_v2`，持有完整签名 `GroupManifest` 和经过验证的设备公钥。Manifest 包含 group/conversation 标识、owner、admins、成员 user、成员 device、role、status、roster version 和 outbox endpoint。因此当前实现不向 Group Outbox provider 或 Cloudflare 隐藏单群 roster、设备关系或角色变化。

Direct / Identity V2 由每个账户自己的 DeviceRegistry Durable Object 协调。该 owner runtime 可以看到本账户设备集合、KeyPackage 库存变化、随机 relationship/ticket/proposal/claim 标识、对端根身份和精确 IdentityBundle revision，以及账户关系和本地设备 join 状态。随机不透明标识避免在 URL 和日志中直接编码双方 user ID，但不能向承载该账户 runtime 的 provider 隐藏“某个经过验证的对端正在与本账户建联”这一事实。

KeyPackage claim、relationship decision 和 Inbox promotion 都在单个 owner Registry 内形成权威事务或可重试投影。实现不假设多个 Inbox Durable Object 之间存在事务，也不会为实现账户关系而建立一个跨所有用户的全局社交图服务。

服务端不能由这些状态解密 MLS application message、附件明文或本地 MLS group secret，但可以观察成员关系和状态变化的时间。

### 2.1 附件预览预取的边界

桌面客户端只会为已经接受的 Direct 会话和已经加入的 Group 随机延迟预取小型图片 preview；Message Request 不触发任何媒体请求，original 始终由用户按需获取。每批最多 20 个 preview，并使用低并发和短抖动，目的是降低“点击图片后立刻访问某个对象”的直接时间关联。

该策略不提供匿名性。发送方 Storage、Transport provider 和网络观察者仍可观察对象密文大小、访问 IP、访问时间及 Range 模式，并可能把这些信号与收件人活动关联。随机延迟既不是匿名中继，也不是流量填充、Tor 或 OHTTP 的替代方案。

## 3. 攻击者与信任边界

- **网络观察者或审查者**：可观察连接目标、IP、时序和尺寸并尝试阻断；TLS 不隐藏目标基础设施和流量模式。
- **Transport provider / Cloudflare**：可读取路由与授权元数据、完整群 manifest 和平台遥测，但不应获得消息或附件解密材料。
- **恶意联系人或群成员**：拥有协议授予的正常视图，可重放、延迟或提交恶意输入；客户端和服务端必须验证签名、epoch、roster transition 和 capability。
- **恶意 owner/admin**：可以执行其角色允许的成员和权限变更；密码学不能阻止合法 owner 滥用管理权。
- **受感染客户端或 WebView**：可以读取该客户端当时可访问的明文和敏感 IPC 结果。显式 challenge 降低意外暴露，不构成对已完全控制进程的防护。
- **本地攻击者**：加密 profile 和系统钥匙串降低静态磁盘泄漏；已解锁进程、剪贴板、屏幕录制和内存读取不在其保护范围内。

## 4. 非目标与剩余风险

当前版本不保证：

- 全局匿名、发送者不可链接性或对强大全局观察者的关系隐藏；
- 向承载某群的 Group Outbox 隐藏该群 roster、设备和角色；
- 隐藏消息长度、访问时序、在线状态或 Cloudflare 账户关系；
- 向某账户自己的 DeviceRegistry provider 隐藏其对端根身份、设备数量、关系状态或 KeyPackage 库存时序；
- 在 endpoint、capability 或客户端已被攻陷时继续保密；
- 对 provider、网络审查者或群管理员的可用性攻击提供绝对防护。

项目仍处于公开 alpha，尚未完成独立第三方安全审计，不应作为高风险或生命安全通信工具。

## 5. 后续研究方向

以下是未来协议研究项，本轮不改变 wire format 或 Group manifest：

- per-group pseudonym，降低同一 user/device 在不同群之间的直接关联；
- 匿名或盲签 capability，减少授权载荷中的稳定身份字段；
- Envelope 和 Blob 尺寸 padding；
- 批处理、延迟窗口、cover traffic 和时序模糊；
- 去标识化路由，使平台 Traces 不再自动收集稳定 user/group/device path；
- 跨 provider 的 Group Outbox 分片、迁移和最小披露授权。

这些机制会增加带宽、延迟、恢复复杂度或权限撤销成本，必须在独立协议版本中设计和验证。
