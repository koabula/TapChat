import { GroupOutboxDurableObject } from "./group-outbox/durable";
import { InboxDurableObject } from "./inbox/durable";
import { DeviceRegistryDurableObject } from "./device-registry/durable";
import { handleRequest } from "./routes/http";
import type { Env } from "./types/env";

export { DeviceRegistryDurableObject, GroupOutboxDurableObject, InboxDurableObject };

export function routeFamilyForObservability(rawUrl: string): string {
  let path = "/";
  try {
    path = new URL(rawUrl).pathname;
  } catch {
    return "invalid_url";
  }
  if (path === "/v1/deployment-bundle") return "deployment_bundle";
  if (path.startsWith("/v2/runtime-auth/")) return "runtime_auth";
  if (path.startsWith("/v1/inbox/")) return "inbox";
  if (path.startsWith("/v1/groups/")) return "group_outbox";
  if (path.startsWith("/v1/group-invite/")) return "group_invite";
  if (path.startsWith("/v1/contact-share/")) return "contact_share";
  if (path.startsWith("/v1/shared-state/")) return "shared_state";
  if (path.startsWith("/v1/storage/")) return "storage";
  if (path.startsWith("/v1/welcome-pickup/")) return "welcome_pickup";
  return "unknown";
}

function logServerFailure(request: Request, status: number): void {
  console.error(JSON.stringify({
    event: "worker_request_failed",
    route_family: routeFamilyForObservability(request.url),
    method: request.method,
    status
  }));
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const response = await handleRequest(request, env);
      if (response.status >= 500) {
        logServerFailure(request, response.status);
      }
      return response;
    } catch {
      logServerFailure(request, 500);
      return Response.json({ error: "internal_error" }, { status: 500 });
    }
  }
} satisfies ExportedHandler<Env>;
