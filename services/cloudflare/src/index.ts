import { GroupOutboxDurableObject } from "./group-outbox/durable";
import { InboxDurableObject } from "./inbox/durable";
import { handleRequest } from "./routes/http";
import type { Env } from "./types/runtime";

export { GroupOutboxDurableObject, InboxDurableObject };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return handleRequest(request, env);
  }
};
