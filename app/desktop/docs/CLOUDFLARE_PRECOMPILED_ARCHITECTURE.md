# Cloudflare Worker Pre-compiled Deployment Architecture

## 概述

将 Cloudflare Worker 部署流程集成到 Desktop App，无需用户手动安装 Node.js 或 wrangler。

## 核心决策

1. **预编译 Worker**: CI/CD 编译 Worker 为单文件 (~50KB)，嵌入 App
2. **嵌入最小化 wrangler**: 只包含 login 功能，获取 OAuth token
3. **使用 Cloudflare REST API**: 直接部署，绕过 wrangler deploy 命令

---

## 1. 预编译 Worker

### Worker 源码位置
`services/cloudflare/src/index.ts` + 所有依赖模块

### 编译命令
```bash
# 使用 wrangler 的 dry-run 模式生成打包文件
wrangler deploy --dry-run --outdir ./dist

# 或使用 esbuild 直接打包
esbuild services/cloudflare/src/index.ts \
  --bundle \
  --format=esm \
  --platform=browser \
  --outfile=app/desktop/src-tauri/embedded/worker.js \
  --minify
```

### CI/CD 流程 (GitHub Actions)
```yaml
name: Build Desktop App
on: [push]

jobs:
  build-worker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      
      - name: Install dependencies
        run: cd services/cloudflare && npm install
      
      - name: Bundle Worker
        run: |
          cd services/cloudflare
          npx wrangler deploy --dry-run --outdir ./bundled
          # Copy to desktop app
          mkdir -p ../desktop/src-tauri/embedded
          cp bundled/index.js ../desktop/src-tauri/embedded/worker.js
      
      - name: Build Desktop
        run: cd app/desktop && cargo build --release
```

### 嵌入位置
```
app/desktop/src-tauri/embedded/
├── worker.js         # 预编译 Worker (~50KB)
├── node/             # Portable Node.js (Linux/macOS)
│   └── bin/node
├── node.exe/         # Portable Node.js (Windows)
│   └── node.exe
└── wrangler/         # 最小化 wrangler (login only)
    └── package.json
    └── index.js      # 自定义 login 实现
```

---

## 2. 最小化 wrangler (Login Only)

### 为什么最小化
完整 wrangler ~100MB，我们只需要 OAuth login 功能 (~5KB 自实现)

### OAuth Login 流程
```
wrangler login 实际上是:
1. 打开浏览器访问 https://dash.cloudflare.com/oauth2/authorize
2. 用户授权后，浏览器重定向到 localhost 带着授权码
3. wrangler 用授权码换取 access_token
4. Token 存储在 ~/.wrangler/config/default.toml
```

### 自实现 Login (无需 wrangler)
```javascript
// embedded/wrangler/login.mjs
import { spawn } from 'child_process';
import http from 'http';

const CLIENT_ID = '54d11594-84e4-41f6-923c-5e63c7af5a3d'; // wrangler 的官方 client_id
const REDIRECT_PORT = 8976;

export async function login() {
  // 1. 启动本地服务器等待回调
  const server = http.createServer();
  server.listen(REDIRECT_PORT);

  // 2. 生成授权 URL
  const authUrl = new URL('https://dash.cloudflare.com/oauth2/authorize');
  authUrl.searchParams.set('client_id', CLIENT_ID);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('redirect_uri', `http://localhost:${REDIRECT_PORT}/oauth/callback`);
  authUrl.searchParams.set('scope', 'account:read account:write workers:write workers:tail workers:r2:read workers:r2:write');

  // 3. 打开浏览器
  spawn(process.platform === 'win32' ? 'cmd' : 'open', [
    process.platform === 'win32' ? '/c' : authUrl.toString(),
    process.platform === 'win32' ? 'start' : authUrl.toString()
  ]);

  // 4. 等待回调获取 code
  const code = await waitForCallback(server);

  // 5. 用 code 换取 token
  const tokenResponse = await fetch('https://dash.cloudflare.com/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: CLIENT_ID,
      redirect_uri: `http://localhost:${REDIRECT_PORT}/oauth/callback`,
    })
  });

  const { access_token, refresh_token } = await tokenResponse.json();
  
  // 6. 存储 token
  return { accessToken: access_token, refreshToken: refresh_token };
}
```

### 使用 wrangler whoami 获取 account_id
Login 后调用:
```bash
node embedded/wrangler/index.js whoami
# 返回: account_id, account_name
```

---

## 3. Cloudflare REST API 部署

### API Endpoints

| 操作 | API Endpoint | 方法 |
|-----|-------------|------|
| 获取账户信息 | `/user/accounts` | GET |
| 上传 Worker | `/accounts/{account_id}/workers/scripts/{name}` | PUT |
| 创建 R2 Bucket | `/accounts/{account_id}/r2/buckets/{name}` | PUT |
| 写入 Secret | `/accounts/{account_id}/workers/scripts/{name}/secrets/{secret}` | PUT |
| 配置 Durable Objects | `/accounts/{account_id}/workers/scripts/{name}/bindings` | PUT |

### 实现流程
```rust
// src-tauri/src/commands/cloudflare_rest.rs

pub async fn deploy_worker_rest(
    account_id: &str,
    api_token: &str,
    worker_name: &str,
    worker_script: &str,  // 预编译的 JS
    config: &WorkerConfig,
) -> Result<DeployResult> {
    let client = Client::new();
    let base = format!("https://api.cloudflare.com/client/v4/accounts/{account_id}");

    // 1. 创建 R2 Buckets
    for bucket in [&config.bucket_name, &config.preview_bucket_name] {
        client.put(format!("{base}/r2/buckets/{bucket}"))
            .header("Authorization", format!("Bearer {api_token}"))
            .json(&serde_json::json!({"name": bucket}))
            .send()
            .await?;
    }

    // 2. 上传 Worker 脚本
    // Worker 脚本需要包含 metadata (bindings, durable objects)
    let worker_payload = build_worker_payload(worker_script, config);
    
    client.put(format!("{base}/workers/scripts/{worker_name}"))
        .header("Authorization", format!("Bearer {api_token}"))
        .header("Content-Type", "application/javascript")
        .body(worker_payload)
        .send()
        .await?;

    // 3. 写入 Secrets
    for (name, value) in [
        ("SHARING_TOKEN_SECRET", &config.sharing_secret),
        ("BOOTSTRAP_TOKEN_SECRET", &config.bootstrap_secret),
    ] {
        client.put(format!("{base}/workers/scripts/{worker_name}/secrets/{name}"))
            .header("Authorization", format!("Bearer {api_token}"))
            .json(&serde_json::json!({"text": value}))
            .send()
            .await?;
    }

    // 4. 获取部署 URL
    Ok(DeployResult {
        worker_url: format!("https://{worker_name}.workers.dev"),
        ..
    })
}

fn build_worker_payload(script: &str, config: &WorkerConfig) -> String {
    // Cloudflare Workers API expects metadata at top of script as comment
    // 或使用 multipart/form-data
    
    // 使用 metadata comment 方式:
    let metadata = serde_json::json!({
        "main_module": "worker.js",
        "compatibility_date": "2024-01-01",
        "compatibility_flags": ["nodejs_compat"],
        "bindings": [
            {
                "type": "durable_object_namespace",
                "name": "INBOX",
                "class_name": "InboxDurableObject"
            },
            {
                "type": "r2_bucket",
                "name": "STORAGE",
                "bucket_name": config.bucket_name
            }
        ]
    });
    
    format!(
        "// @cloudflare metadata: {}\n{}",
        metadata.to_string(),
        script
    )
}
```

---

## 4. Desktop App 用户流程

### UI 流程
```
┌─────────────────────────────────────────────────────────────┐
│  设置向导: Cloudflare 部署                                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  [Step 1] 检查授权状态                                       │
│  ○ 已授权: 显示账户信息                                      │
│  ● 未授权: 显示"连接 Cloudflare"按钮                         │
│                                                             │
│  点击按钮 →                                                 │
│  ┌───────────────────────────────────────┐                  │
│  │ 正在打开浏览器...                      │                  │
│  │ 请在浏览器中完成 Cloudflare 授权       │                  │
│  │                                       │                  │
│  │ 完成后自动返回此页面                   │                  │
│  └───────────────────────────────────────┘                  │
│                                                             │
│  [Step 2] 部署配置                                          │
│  Worker 名称: tapchat-<user-id>                             │
│  区域: global                                               │
│                                                             │
│  [Step 3] 部署                                              │
│  ┌───────────────────────────────────────┐                  │
│  │ 正在部署...                            │                  │
│  │ ████████████░░░░░░░░ 65%              │                  │
│  │ - 创建存储桶 ✓                         │                  │
│  │ - 上传 Worker ✓                        │                  │
│  │ - 配置密钥 ⏳                          │                  │
│  │ - 验证部署 ⏳                          │                  │
│  └───────────────────────────────────────┘                  │
│                                                             │
│  [Step 4] 完成!                                             │
│  Worker URL: https://tapchat-xxx.workers.dev                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Rust 实现
```rust
// src-tauri/src/commands/cloudflare_flow.rs

#[tauri::command]
pub async fn cloudflare_oauth_login(app: AppHandle) -> Result<OAuthResult, String> {
    // 使用嵌入的 login.mjs
    let runtime_root = resolve_embedded_runtime_root()
        .ok_or_else(|| "Embedded runtime not found")?;
    
    let login_script = runtime_root.join("wrangler").join("login.mjs");
    let node_path = resolve_embedded_node();
    
    // 运行 login 脚本
    let output = tokio::process::Command::new(node_path)
        .arg(&login_script)
        .output()
        .await
        .map_err(|e| e.to_string())?;
    
    // 解析返回的 token
    let result: OAuthResult = serde_json::from_str(&output.stdout)
        .map_err(|e| e.to_string())?;
    
    // 存储 token 到安全位置
    save_oauth_token(&app, &result)?;
    
    Ok(result)
}

#[tauri::command]
pub async fn cloudflare_full_deploy(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<DeployResult, String> {
    // 1. 检查/获取 OAuth token
    let token = get_or_request_oauth_token(&app)?;
    
    // 2. 获取 account_id (whoami)
    let account_id = get_account_id(&token)?;
    
    // 3. 加载预编译 Worker
    let worker_script = load_embedded_worker()?;
    
    // 4. 生成配置
    let config = generate_deploy_config(&state)?;
    
    // 5. 使用 REST API 部署
    let result = deploy_worker_rest(&account_id, &token, &config, &worker_script)?;
    
    // 6. Bootstrap
    bootstrap_and_import(&result, &state)?;
    
    Ok(result)
}
```

---

## 5. 文件结构

### 最终嵌入结构
```
app/desktop/src-tauri/embedded/
├── worker.js                  # 预编译 Worker (~50KB)
├── wrangler/
│   ├── login.mjs              # OAuth login 实现 (~3KB)
│   ├── whoami.mjs             # 获取账户信息 (~2KB)
│   └── package.json           # 仅声明依赖
└── node/                      # Portable Node.js
    ├── win-x64/
    │   └── node.exe
    ├── linux-x64/
    │   └── bin/node
    └── darwin-x64/
        └── bin/node
```

### Cargo.toml 配置
```toml
[bundle]
resources = [
    "embedded/worker.js",
    "embedded/wrangler/*",
    "embedded/node/**/*"
]
```

---

## 6. 待实现任务

### Phase 1: 基础设施
- [ ] 创建 `embedded/` 目录结构
- [ ] 编写 `login.mjs` OAuth 实现
- [ ] 编写 `whoami.mjs` 获取账户信息
- [ ] 测试 OAuth 流程

### Phase 2: REST API 部署
- [ ] 实现 `cloudflare_rest.rs` 模块
- [ ] 实现 R2 bucket 创建
- [ ] 实现 Worker 上传 (带 bindings)
- [ ] 实现 Secrets 写入
- [ ] 测试完整部署流程

### Phase 3: CI/CD
- [ ] GitHub Action 编译 Worker
- [ ] 自动复制到 embedded/
- [ ] 打包 Portable Node.js
- [ ] 测试端到端流程

### Phase 4: UI 集成
- [ ] 更新设置向导 UI
- [ ] 进度显示
- [ ] 错误处理
- [ ] 重新部署/撤销

---

## 7. 替代方案对比

| 方案 | 优点 | 缺点 |
|-----|------|------|
| **预编译 + REST API** | ~50KB, 无需 wrangler | 需要手动实现 API 调用 |
| 嵌入完整 wrangler | 功能完整 | ~100MB, 需要完整 Node.js |
| 系统安装 wrangler | 最简单 | 用户需要手动安装 |

选择预编译方案是最佳平衡点。