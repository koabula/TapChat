import { unstable_dev } from "wrangler";

const port = Number(process.env.TAPCHAT_PHASE10_PORT ?? "0");
const persistTo = process.env.TAPCHAT_PHASE10_PERSIST_TO;
const sharingSecret = process.env.TAPCHAT_PHASE10_SHARING_SECRET ?? "phase10-sharing-secret";
const bootstrapSecret = process.env.TAPCHAT_PHASE10_BOOTSTRAP_SECRET ?? "phase10-bootstrap-secret";
const baseUrl = `http://127.0.0.1:${port}`;

const worker = await unstable_dev("src/index.ts", {
  config: "wrangler.toml",
  local: true,
  ip: "127.0.0.1",
  port,
  persist: Boolean(persistTo),
  persistTo,
  logLevel: "error",
  vars: {
    PUBLIC_BASE_URL: baseUrl,
    DEPLOYMENT_REGION: "local-phase10",
    SHARING_TOKEN_SECRET: sharingSecret,
    BOOTSTRAP_TOKEN_SECRET: bootstrapSecret
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
  bootstrapSecret
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
