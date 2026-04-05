# Cloudflare Manual Deployment

This document turns the current Cloudflare reference implementation into a repeatable manual Wrangler deployment flow.

## Scope

This deployment guide covers:

- Worker + Durable Object inbox
- R2-backed storage
- WebSocket `Inbox.Subscribe`
- device bootstrap and deployment bundle issuance
- shared-state and keypackage writes

This guide does not cover:

- Wakeup bridge
- Terraform or one-click provisioning
- multi-region failover

## Prerequisites

- Cloudflare account with Workers, Durable Objects, and R2 enabled
- Node.js 22+
- npm dependencies installed in `services/cloudflare`
- Wrangler authenticated against the target account

## Required bindings

`services/cloudflare/wrangler.toml` already defines the base topology:

- Durable Object binding: `INBOX`
- R2 bucket binding: `TAPCHAT_STORAGE`
- Worker entrypoint: `src/index.ts`

Before first deploy, create the R2 bucket and ensure the Durable Object migration tag remains in sync with the deployed schema.

## Required vars and secrets

Set these per environment before deploying:

- `PUBLIC_BASE_URL`
  - The final HTTPS origin for the Worker, such as `https://tapchat-worker.example.workers.dev`
- `DEPLOYMENT_REGION`
  - A stable operator label such as `us-east-1` or `global`
- `MAX_INLINE_BYTES`
  - Recommended initial value: `4096`
- `RETENTION_DAYS`
  - Recommended initial value: `30`
- `RATE_LIMIT_PER_MINUTE`
  - Recommended initial value: `60`
- `RATE_LIMIT_PER_HOUR`
  - Recommended initial value: `600`

Secrets:

- `SHARING_TOKEN_SECRET`
  - Signs device runtime tokens, shared-state write tokens, keypackage write tokens, and storage sharing URLs
- `BOOTSTRAP_TOKEN_SECRET`
  - Signs bootstrap tokens used to issue a device deployment bundle

Example commands:

```powershell
cd D:\Code\TapChat\services\cloudflare
npx wrangler secret put SHARING_TOKEN_SECRET
npx wrangler secret put BOOTSTRAP_TOKEN_SECRET
```

## Deploy

```powershell
cd D:\Code\TapChat\services\cloudflare
npm run check
npm test
npm run test:integration
npx wrangler deploy
```

After deploy, confirm the Worker URL matches `PUBLIC_BASE_URL`.

## Deployment bundle flow

TapChat clients do not consume raw Wrangler output. They consume a deployment bundle issued by the bootstrap route.

The bundle must include:

- `inbox_http_endpoint`
- `inbox_websocket_endpoint`
- `storage_base_info`
- `runtime_config`
- `device_runtime_auth`

Manual issuance flow:

1. Construct a bootstrap token signed with `BOOTSTRAP_TOKEN_SECRET`.
2. Call `POST /v1/bootstrap/device` with:
   - `userId`
   - `deviceId`
   - model `version`
3. Import the returned deployment bundle into the client profile.
4. Publish the local identity bundle using `device_runtime_auth`.

The bootstrap token must:

- use service `bootstrap`
- include `operations: ["issue_device_bundle"]`
- match the target `userId`
- match the target `deviceId`
- have a short expiry

## Shared-state and keypackage publishing

After importing the deployment bundle, the client should publish:

- identity bundle
- device status
- keypackage refs and objects

Those writes use the `device_runtime_auth` token returned in the deployment bundle. No long-lived Cloudflare API token should be embedded in the client.

## Smoke checklist

After every deploy, run this checklist against the deployed Worker:

1. `POST /v1/bootstrap/device` returns a deployment bundle with `deviceRuntimeAuth`.
2. `GET /v1/inbox/{deviceId}/head` succeeds with the returned runtime token.
3. `GET /v1/inbox/{deviceId}/messages?fromSeq=1&limit=10` succeeds with the returned runtime token.
4. `POST /v1/inbox/{deviceId}/ack` succeeds with the returned runtime token.
5. `GET /v1/inbox/{deviceId}/subscribe` upgrades to WebSocket with the returned runtime token.
6. `POST /v1/storage/prepare-upload` returns upload and download targets.
7. Upload and download both succeed for a prepared blob.
8. `PUT /v1/shared-state/{userId}/identity-bundle` succeeds with the returned runtime token.
9. message requests and allowlist routes behave as expected for a non-allowlisted sender.

## Token lifecycle

Recommended operational rules:

- Bootstrap tokens should be short-lived and minted only for operator-assisted provisioning.
- `device_runtime_auth` should be treated as an environment-scoped runtime capability, not a permanent credential.
- Storage sharing URLs should be treated as short-lived bearer URLs.
- Rotation of `SHARING_TOKEN_SECRET` invalidates previously issued runtime tokens and sharing URLs.
- Rotation of `BOOTSTRAP_TOKEN_SECRET` invalidates previously issued bootstrap tokens, but does not revoke already issued runtime tokens.

## Rotation workflow

### Rotate `BOOTSTRAP_TOKEN_SECRET`

Use when bootstrap tokens leak.

1. Write a new `BOOTSTRAP_TOKEN_SECRET`.
2. Redeploy the Worker.
3. Reissue bootstrap tokens for any still-pending provisioning flow.

Existing runtime tokens continue to work.

### Rotate `SHARING_TOKEN_SECRET`

Use when runtime tokens or sharing URLs leak.

1. Write a new `SHARING_TOKEN_SECRET`.
2. Redeploy the Worker.
3. Re-bootstrap affected devices to obtain a fresh deployment bundle.
4. Re-import the deployment bundle into those devices.
5. Re-publish identity bundle, device status, and keypackage refs if required by the recovery flow.

After this rotation, old runtime tokens and old blob sharing URLs should fail authorization.

## Failure modes

- `401 invalid_capability`
  - token missing, expired, signed with the wrong secret, or malformed
- `403 invalid_capability`
  - token service, scope, path binding, or object binding does not match the request
- `413`
  - append payload exceeds `MAX_INLINE_BYTES`
- `429`
  - sender-recipient rate limit triggered

## Operator notes

- The Cloudflare Worker is the only public edge entrypoint.
- Durable Objects and R2 stay behind Worker routing and secrets.
- Clients should never receive a Cloudflare management API token.
- Desktop continues to rely on `Inbox.Subscribe` plus `head + fetch + ack` recovery; Wakeup remains out of scope for this deployment.
