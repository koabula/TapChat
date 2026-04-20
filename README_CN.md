# TapChat

一个面向抗审查和元数据隐私的去中心化即时通信应用。

## 项目概览

TapChat 是一个去中心化即时通信系统。每个用户拥有并控制自己的传输基础设施组件。整体架构由以下部分组成：

- **Client**：本地客户端核心，负责状态管理、加密与解密。只有 Client 会接触消息明文。
- **Inbox**：消息队列与消息索引的真实来源。
- **Storage**：用于附件和大消息的 Blob 存储服务。
- **Wakeup**：通知组件，用于提醒客户端同步 Inbox；对于桌面端可以是可选组件。

这些组件都由用户自行部署和持有，因此不会有一个中心化服务器统一掌握所有消息和元数据。

## 特性

- 基于 OpenMLS 的端到端加密，兼容 MLS（RFC 9420）
- 去中心化架构，每个用户拥有自己的传输组件
- 面向元数据隐私的消息传输设计
- 支持基于 WebSocket 的实时订阅
- 基于 BIP39 / BIP32 的跨设备身份派生模型

## 项目结构

```text
src/                     # Rust core 库
  identity/              # BIP39 身份系统
  mls_adapter/           # OpenMLS 集成
  model/                 # 核心数据结构
  ffi_api/               # 面向平台绑定的 FFI 接口

services/cloudflare/     # Cloudflare 参考后端实现
  inbox/                 # Inbox Durable Object
  storage/               # 基于 R2 的 Blob 存储

app/desktop/             # Tauri 桌面应用
  src/                   # React 前端
  src-tauri/             # Rust 后端绑定
```

## 当前状态

**v0.1**：当前仓库已经具备 1 对 1 私聊主链路的实现，并包含 Rust core、Cloudflare 参考传输层和桌面端应用。

## 快速开始

你可以在 [GitHub Releases](https://github.com/koabula/TapChat/releases) 页面获取最新的安装包。
使用 TapChat Desktop 需要一个 Cloudflare 账户，并开通 Worker 和 R2 对象存储服务。

### 初始化

第一次进入 TapChat 需要创建一个 Profile，请按照 App 的引导进行初始化。在 Step 4 会跳转至 Cloudflare 登录界面，请授权后回到 TapChat 继续下一步。

### 添加好友

TapChat 并没有一个中心服务器来进行好友查找。我们使用 Share Link 来让好友能够添加我们。你可以在 Setting > Account 中复制和轮换你的 Share Link。

![界面截图](./image/image.png)

在获取好友的 Share Link 之后，你需要点击主界面左下角的 + 按钮，粘贴 Share Link，就可以看到好友的信息。之后点击 Chat，就会自动发送好友请求。

在收到好友请求后，会在 Message Request 中进行提示，点击进入后可以选择同意。

之后，双方就可以开始聊天。

## 开发环境

### 前置依赖

- Rust 1.70+
- Node.js 18+
- Cloudflare 账户（用于部署参考后端）

### 构建

```bash
# 构建 Rust core
cargo build

# 启动桌面端
cd app/desktop
npm install
npm run tauri:dev
```


## License

MIT
