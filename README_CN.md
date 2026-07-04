# TapChat

[English](./README.md) | 中文

面向抗审查和元数据隐私的用户自带传输层即时通信应用。

TapChat 目前是早期公开 alpha，适合实验、协议反馈和小规模试用。项目尚未经过外部安全审计，不应在高风险通信场景中依赖。

## TapChat 是什么？

TapChat 是一个端到端加密即时通信应用，每个用户都拥有自己的传输组件。消息不经过一个统一的 TapChat 中心服务器，而是由每个用户自行部署 Inbox 和 Storage，并通过受限 capability 授权联系人发送消息。

客户端是唯一处理消息明文的地方。当前桌面端参考实现可以把传输层部署到用户自己的 Cloudflare 账户中。

## 为什么是用户自带传输层？

大多数即时通信系统仍依赖中心服务来完成消息投递、账号状态和元数据聚合。TapChat 探索另一种模型：

- 用户控制自己接收消息所需的传输层
- 联系人只获得发送加密 Envelope 所需的最小权限
- 消息历史通过 cursor 同步，而不是依赖 best-effort 推送状态
- 附件会先在本地加密，再作为 blob 上传

这并不会消除所有元数据。网络时序、Cloudflare 账号层面的元数据和联系人关系线索仍然可能存在。TapChat 的目标是在保持可用性的前提下，降低中心化控制和元数据集中度。

## 工作方式

![TapChat 架构](./image/readme-architecture.svg)

- **Client** 在本地运行，持有身份状态，执行加密与解密，并管理会话。
- **Inbox** 是小消息 Envelope 和消息索引的真实来源。
- **Storage** 存储附件和大消息等加密 blob。
- **Inbox.Subscribe** 为桌面端提供在线 WebSocket 同步路径。
- **Wakeup** 是未来用于移动端和后台同步的 best-effort 通知层。

TapChat 当前提供基于 Cloudflare Workers、Durable Objects、WebSocket 和 R2 的参考传输层。协议设计上允许后续接入其他传输实现。

## 当前状态

| 范围 | 状态 |
| --- | --- |
| 可用于 alpha 试用 | 桌面端、私聊、Cloudflare 参考传输层、附件、WebSocket 同步 |
| 已可试用但可能不稳定 | 群聊 |
| 开发中 | 多设备支持、备份与恢复 |
| 尚未完成 | 移动端 wakeup bridge、外部安全审计、生产规模部署指南 |

群聊功能已经可以进行早期试用，但仍可能存在 bug。多设备支持和备份/恢复功能正在开发中，尚未加入当前 release。

## 试用桌面端 alpha

1. 从 [GitHub Releases](https://github.com/koabula/TapChat/releases) 下载最新安装包。
2. 准备一个已开通 Workers、Durable Objects 和 R2 的 Cloudflare 账户。
3. 打开 TapChat Desktop，并按照下面的初始化流程完成设置。
4. 与可信联系人交换 Share Link 后即可开始聊天。

当前 alpha 没有中心化 TapChat 目录，也没有用户名搜索。联系人发现有意保持为手动交换。

## 如何使用

### 初始化

**1. 开始初始化。** 打开 TapChat，选择创建新身份或恢复已有身份。

![TapChat 初始化首页](./image/screenshots/onboarding-start.png)

**2. 创建本地 profile。** 设置本地 profile 名称，也可以选择为当前设备设置 passphrase。

![TapChat 创建 profile 界面](./image/screenshots/onboarding-profile.png)

**3. 备份恢复助记词。** 继续之前请安全保存恢复助记词；它是恢复身份所必需的凭证。

![TapChat 恢复助记词备份界面](./image/screenshots/onboarding-recovery-phrase.png)

**4. 部署或连接 Cloudflare runtime。** 连接 Cloudflare，部署 Inbox 和 Storage runtime，然后确认 endpoint 可以访问。

![TapChat Cloudflare runtime 部署界面](./image/screenshots/onboarding-cloudflare-runtime.png)

### 聊天

**1. 复制你的 Share Link。** 打开 Settings > Account，复制要分享给联系人的链接。

![TapChat Share Link 界面](./image/screenshots/chat-share-link.png)

**2. 添加联系人。** 粘贴对方的 Share Link，点击 Add，然后进入聊天。

![TapChat 添加联系人界面](./image/screenshots/chat-add-contact.png)

**3. 接受消息请求。** 对方接受 Message Request 后，双方即可开始聊天。

![TapChat 消息请求界面](./image/screenshots/chat-message-request.png)

## 开发环境

前置依赖：

- Rust stable
- Node.js 20+
- 用于真实传输层部署的 Cloudflare 账户

常用命令：

```bash
# Rust core
cargo build
cargo test -q --lib

# Cloudflare 参考传输层
cd services/cloudflare
npm install
npm run check
npm test

# 桌面端
cd app/desktop
npm install
npm run tauri:dev
```

## 安全说明

- 消息明文应只存在于客户端。
- Cloudflare 参考传输层只负责存储和路由加密 Envelope 与加密 blob，不应具备解密消息内容的能力。
- TapChat 仍会暴露部分元数据，例如网络时序、endpoint 访问、账号层基础设施和用户部署方式带来的信息。
- 项目尚未经过第三方安全审计。
- 请不要把当前 alpha 用于高风险或生命安全相关通信。

## 项目结构

```text
src/                     Rust core 和 CLI
  identity/              基于 BIP39/BIP32 的用户身份与设备绑定
  mls_adapter/           OpenMLS 集成
  ffi_api/               面向平台绑定的 command/event/effect API
  transport_contract/    面向传输层的请求与响应类型

services/cloudflare/     Cloudflare 参考传输层
  src/inbox/             每设备 Inbox Durable Object
  src/storage/           基于 R2 的加密 blob 存储
  src/group-outbox/      实验性群聊 outbox

app/desktop/             Tauri 桌面端
  src/                   React UI
  src-tauri/             Rust 桌面后端与平台端口
```

## 许可证

MIT
