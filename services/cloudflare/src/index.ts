import { InboxDurableObject } from "./inbox/durable";
import { handleRequest } from "./routes/http";
import type { Env } from "./types/runtime";

export { InboxDurableObject };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return handleRequest(request, env);
  }
};
