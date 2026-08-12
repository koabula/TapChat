import { unstable_dev } from "wrangler";

const port = Number(process.env.TAPCHAT_TRANSPORT_PORT ?? "0");
const persistTo = process.env.TAPCHAT_TRANSPORT_PERSIST_TO;
const sharingSecret = process.env.TAPCHAT_TRANSPORT_SHARING_SECRET ?? "transport-sharing-secret-0123456789abcdef0123456789abcdef";
const runtimeSecret = process.env.TAPCHAT_TRANSPORT_RUNTIME_SECRET ?? "transport-runtime-secret-0123456789abcdef0123456789abcdef";
const runtimeId = process.env.TAPCHAT_TRANSPORT_RUNTIME_ID;
const ownerUserId = process.env.TAPCHAT_TRANSPORT_OWNER_USER_ID;
const ownerUserPublicKey = process.env.TAPCHAT_TRANSPORT_OWNER_USER_PUBLIC_KEY;
if (!runtimeId || !ownerUserId || !ownerUserPublicKey) {
  throw new Error("local runtime requires runtime id and owner identity variables");
}
const maxInlineBytes = process.env.MAX_INLINE_BYTES;
const retentionDays = process.env.RETENTION_DAYS;
const rateLimitPerMinute = process.env.RATE_LIMIT_PER_MINUTE;
const rateLimitPerHour = process.env.RATE_LIMIT_PER_HOUR;
const baseUrl = `http://127.0.0.1:${port}`;

const worker = await unstable_dev("src/index.ts", {
  config: "wrangler.jsonc",
  local: true,
  ip: "127.0.0.1",
  port,
  persist: Boolean(persistTo),
  persistTo,
  logLevel: "error",
  vars: {
    PUBLIC_BASE_URL: baseUrl,
    RUNTIME_ID: runtimeId,
    OWNER_USER_ID: ownerUserId,
    OWNER_USER_PUBLIC_KEY: ownerUserPublicKey,
    DEPLOYMENT_REGION: "local-transport",
    SHARING_INTERNAL_SECRET: sharingSecret,
    DEVICE_RUNTIME_SECRET: runtimeSecret,
    DEVICE_RUNTIME_SECRET_KEY_ID: "local-runtime-current",
    ...(maxInlineBytes ? { MAX_INLINE_BYTES: maxInlineBytes } : {}),
    ...(retentionDays ? { RETENTION_DAYS: retentionDays } : {}),
    ...(rateLimitPerMinute ? { RATE_LIMIT_PER_MINUTE: rateLimitPerMinute } : {}),
    ...(rateLimitPerHour ? { RATE_LIMIT_PER_HOUR: rateLimitPerHour } : {})
  },
  experimental: {
    disableExperimentalWarning: true,
    watch: false,
    testMode: true
  }
});

const metadata = {
  address: worker.address,
  port: worker.port,
  baseUrl,
  websocketBaseUrl: baseUrl.replace(/^http/i, "ws"),
  sharingSecret,
  runtimeId
};
process.stdout.write(`${JSON.stringify(metadata)}\n`);

let shuttingDown = false;
async function shutdown() {
  if (shuttingDown) {
    return;
  }
  shuttingDown = true;
  try {
    await worker.stop();
  } finally {
    process.exit(0);
  }
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
process.stdin.resume();
process.stdin.on("end", shutdown);

await new Promise(() => {});
