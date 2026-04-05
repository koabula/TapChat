# Cloudflare 部署指南

使用本地部署向导，把 Cloudflare 参考实现部署到真实的 Cloudflare 环境。这个流程在用户自己的电脑上执行，不是在 Cloudflare 控制台里执行。

推荐给最终用户的入口：

- `cargo run --bin tapchat -- --output json runtime cloudflare provision auto --profile <profile-dir>`
- `cargo run --bin tapchat -- --output json runtime cloudflare provision custom --profile <profile-dir>`

独立脚本继续保留给开发 / 运维 / 调试场景：

- `npm run deploy:cloudflare`

## 脚本会做什么

执行 `npm run deploy:cloudflare` 后，脚本会自动完成：
- 检查本地环境是否满足要求
- 检查 Wrangler 登录状态，未登录时自动启动 `wrangler login`
- 交互式采集部署变量和 secrets
- 创建或复用所需的 R2 bucket
- 写入 Cloudflare secrets
- 运行 `npm run check`、`npm test`、`npm run test:integration`
- 使用临时 Wrangler 配置执行部署

脚本会部署以下组件：

- Worker + Durable Object inbox
- 基于 R2 的 storage
- WebSocket `Inbox.Subscribe`
- bootstrap、shared-state 和 keypackage 路由

本指南不覆盖：

- Wakeup bridge
- Terraform
- 在 TapChat CLI 内直接完成 device bootstrap

## 前置条件

- 已开通 Workers、Durable Objects 和 R2 的 Cloudflare 账号
- Node.js 22+
- 已在 `D:\Code\TapChat\services\cloudflare` 安装 npm 依赖
- 可以在本地终端执行部署脚本

脚本使用本机 Wrangler 登录态作为 Cloudflare 权限来源。如果尚未登录，它会自动拉起 Cloudflare 浏览器登录流程。

## 使用方法

```powershell
cd D:\Code\TapChat\services\cloudflare
npm run deploy:cloudflare
```

这个命令在本地执行，但会把服务部署到与你的 Wrangler 登录账号对应的真实 Cloudflare 环境。

## 脚本会要求输入的参数

Vars：

- `worker_name`
- `PUBLIC_BASE_URL`
- `DEPLOYMENT_REGION`
- `MAX_INLINE_BYTES`，默认 `4096`
- `RETENTION_DAYS`，默认 `30`
- `RATE_LIMIT_PER_MINUTE`，默认 `60`
- `RATE_LIMIT_PER_HOUR`，默认 `600`
- `bucket_name`，默认 `<worker_name>-storage`
- `preview_bucket_name`，默认 `<worker_name>-storage-preview`

Secrets：

- `SHARING_TOKEN_SECRET`
- `BOOTSTRAP_TOKEN_SECRET`

Secrets 通过 `wrangler secret put` 写入，不会进入临时 Wrangler 配置文件。

## 部署完成后的结果

脚本成功后，目标 Cloudflare 账号中会具备：

- 已部署的 Worker
- 所需 Durable Object migration
- 所需 R2 bucket 绑定
- 已写入的 vars 和 secrets

脚本会输出 Worker 名称、`PUBLIC_BASE_URL`、storage bucket 名称。下一步仍需要手工 bootstrap 一个设备，并把返回的 deployment bundle 导入 TapChat profile。

bootstrap 路由返回的 deployment bundle 包含：

- `inbox_http_endpoint`
- `inbox_websocket_endpoint`
- `storage_base_info`
- `runtime_config`
- `device_runtime_auth`

## Bootstrap 与发布流程

部署完成后：

1. 用 `BOOTSTRAP_TOKEN_SECRET` 签发 bootstrap token。
2. 调用 `POST /v1/bootstrap/device`，传入 `userId`、`deviceId` 和模型 `version`。
3. 把返回的 deployment bundle 导入客户端 profile。
4. 使用 `device_runtime_auth` 发布本地 identity bundle、device status 和 keypackage refs/objects。

客户端不应接触 Cloudflare 管理 API token。

## 故障排查

### Wrangler 登录失败

- 单独执行 `npx wrangler login`
- 确认浏览器中的 Cloudflare 授权流程完成
- 然后重新执行 `npm run deploy:cloudflare`

### Bucket 创建失败

- 确认目标账号已开通 R2
- 确认 bucket 名在目标账号中可用
- 如有需要，重新运行脚本并换一个 bucket 名

### Secret 写入失败

- 确认 Wrangler 已登录到正确账号
- 确认该账号对目标 Worker 有修改 secret 的权限

### 预检测试失败

- 先修复本地 `check`、`test` 或 `test:integration` 的失败
- 脚本会在测试失败时阻止部署

### Deploy URL 与 `PUBLIC_BASE_URL` 不一致

- 如果你使用的是 `*.workers.dev` 域名，这两者应该直接一致
- 如果你使用的是自定义域名，需要手工确认 Worker route 和 DNS 映射

### 常见运行时错误

- `401 invalid_capability`
  - token 缺失、过期、格式错误，或签名 secret 不匹配
- `403 invalid_capability`
  - token 的 service、scope、path binding 或 object binding 与请求不匹配
- `413`
  - append payload 超过 `MAX_INLINE_BYTES`
- `429`
  - 触发 sender-recipient 级 rate limit


## 真实 Cloudflare Smoke Runbook

当 `runtime cloudflare provision auto/custom` 成功后，建议按这个顺序验证真实部署：

1. 运行 `cargo run --bin tapchat -- --output json runtime cloudflare status --profile <profile-dir>`，确认 `mode`、`worker_name`、`public_base_url`、`deployment_bound`。
2. 导出当前本地 identity bundle，并把它导入到另一个绑定同一 deployment 的 profile。
3. 用两个 profile 建立 direct conversation，并发送一条文本消息。
4. 在接收端执行 `sync once`，确认消息只落盘一次。
5. 发送一个附件，再次 `sync once`，并在接收端完成下载。
6. 运行 `sync status`，确认 `checkpoint`、`realtime`、`pending_outbox`、`pending_blob_uploads` 状态健康。
7. 运行 `runtime cloudflare redeploy --profile <profile-dir>`，确认 `runtime cloudflare status` 仍报告相同 deployment 绑定。
8. 运行 `runtime cloudflare rotate-secrets --profile <profile-dir>`，确认当前设备仍可 bootstrap/import。
9. 只在一次性测试 profile 上运行 `runtime cloudflare detach --profile <profile-dir>`，确认 `deployment_bound` 变为 `false`。

建议先在 staging 或低风险 Worker 上完成这一整套 runbook，再考虑继续扩展到更正式的生产流量。
