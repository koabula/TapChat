# Cloudflare Deployment

Use the local deployment wizard to provision the Cloudflare reference transport into a real Cloudflare account. This flow runs on your machine, not in the Cloudflare dashboard.

Recommended user entry:

- `cargo run --bin tapchat -- --output json runtime cloudflare provision auto --profile <profile-dir>`
- `cargo run --bin tapchat -- --output json runtime cloudflare provision custom --profile <profile-dir>`

The standalone script remains available for development and operator debugging:

- `npm run deploy:cloudflare`

## What the script does

`npm run deploy:cloudflare` performs the full operator flow:
- verifies local prerequisites
- checks Wrangler authentication and auto-starts `wrangler login` if needed
- collects deployment vars and secrets interactively
- creates or reuses the required R2 buckets
- writes Cloudflare secrets
- runs `npm run check`, `npm test`, and `npm run test:integration`
- deploys the Worker with a temporary Wrangler config

The script deploys:

- Worker + Durable Object inbox
- R2-backed storage
- WebSocket `Inbox.Subscribe`
- bootstrap, shared-state, and keypackage routes

This guide does not cover:

- Wakeup bridge
- Terraform
- direct device bootstrap automation inside TapChat CLI

## Prerequisites

- Cloudflare account with Workers, Durable Objects, and R2 enabled
- Node.js 22+
- npm dependencies installed in `D:\Code\TapChat\services\cloudflare`
- local terminal access on the machine that will run the deployment

The script uses your local Wrangler session as the Cloudflare permission source. If you are not logged in, it opens the standard Cloudflare browser login flow.

## Usage

```powershell
cd D:\Code\TapChat\services\cloudflare
npm run deploy:cloudflare
```

The script runs locally and deploys to the real Cloudflare environment tied to your Wrangler login.

## Inputs the script asks for

Vars:

- `worker_name`
- `PUBLIC_BASE_URL`
- `DEPLOYMENT_REGION`
- `MAX_INLINE_BYTES` default `4096`
- `RETENTION_DAYS` default `30`
- `RATE_LIMIT_PER_MINUTE` default `60`
- `RATE_LIMIT_PER_HOUR` default `600`
- `bucket_name` default `<worker_name>-storage`
- `preview_bucket_name` default `<worker_name>-storage-preview`

Secrets:

- `SHARING_TOKEN_SECRET`
- `BOOTSTRAP_TOKEN_SECRET`

Secrets are written with `wrangler secret put` and are not stored in the temporary Wrangler config file.

## Result after deploy

After the script succeeds, the target Cloudflare account has:

- a deployed Worker
- the required Durable Object migration
- the required R2 bucket bindings
- the configured vars and secrets

The script prints the Worker name, `PUBLIC_BASE_URL`, and storage bucket names. The next manual step is still to bootstrap a device and import the returned deployment bundle into a TapChat profile.

The bootstrap route returns a deployment bundle that includes:

- `inbox_http_endpoint`
- `inbox_websocket_endpoint`
- `storage_base_info`
- `runtime_config`
- `device_runtime_auth`

## Bootstrap and publishing flow

After deployment:

1. Mint a bootstrap token signed with `BOOTSTRAP_TOKEN_SECRET`.
2. Call `POST /v1/bootstrap/device` with `userId`, `deviceId`, and model `version`.
3. Import the returned deployment bundle into the client profile.
4. Publish the local identity bundle, device status, and keypackage refs/objects using `device_runtime_auth`.

Clients should never receive a Cloudflare management API token.

## Troubleshooting

### Wrangler login fails

- Re-run `npx wrangler login`
- Confirm the browser-based Cloudflare authorization completes
- Re-run `npm run deploy:cloudflare`

### Bucket creation fails

- Confirm the target account has R2 enabled
- Check whether the bucket name is already taken in the target account
- Re-run the script with a different bucket name if required

### Secret write fails

- Confirm Wrangler is authenticated against the correct account
- Verify you have permission to update Worker secrets in that account

### Pre-deploy tests fail

- Fix the failing local check before deploying
- The script intentionally blocks deployment when `check`, `test`, or `test:integration` is red

### Deploy URL and `PUBLIC_BASE_URL` do not match

- If you use a `*.workers.dev` origin, they should match directly
- If you use a custom domain, confirm the Worker route and DNS mapping manually

### Common runtime errors

- `401 invalid_capability`
  - token missing, expired, malformed, or signed with the wrong secret
- `403 invalid_capability`
  - token service, scope, path binding, or object binding does not match the request
- `413`
  - append payload exceeds `MAX_INLINE_BYTES`
- `429`
  - sender-recipient rate limit triggered

