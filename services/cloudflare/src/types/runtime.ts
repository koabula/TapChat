export interface DurableObjectId {}

export interface DurableObjectStub {
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

export interface DurableObjectNamespace {
  idFromName(name: string): DurableObjectId;
  get(id: DurableObjectId): DurableObjectStub;
}

export interface R2ObjectBody {
  json<T = unknown>(): Promise<T>;
  arrayBuffer(): Promise<ArrayBuffer>;
}

export interface R2Bucket {
  put(key: string, value: string | ArrayBuffer | ArrayBufferView, options?: unknown): Promise<unknown>;
  get(key: string): Promise<R2ObjectBody | null>;
  delete(key: string): Promise<void>;
}

export interface Env {
  INBOX: DurableObjectNamespace;
  TAPCHAT_STORAGE: R2Bucket;
  PUBLIC_BASE_URL?: string;
  DEPLOYMENT_REGION?: string;
  MAX_INLINE_BYTES?: string;
  RETENTION_DAYS?: string;
  SHARING_TOKEN_SECRET?: string;
  BOOTSTRAP_TOKEN_SECRET?: string;
}

export interface DurableObjectStorageLike {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<void>;
  setAlarm(epochMillis: number): Promise<void>;
}

export interface JsonBlobStore {
  putJson<T>(key: string, value: T): Promise<void>;
  getJson<T>(key: string): Promise<T | null>;
  putBytes(key: string, value: ArrayBuffer | Uint8Array, metadata?: Record<string, string>): Promise<void>;
  getBytes(key: string): Promise<ArrayBuffer | null>;
  delete(key: string): Promise<void>;
}

export interface SessionSink {
  send(payload: string): void;
}
