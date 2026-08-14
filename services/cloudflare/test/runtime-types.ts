export interface DurableObjectId {}

export interface DurableObjectStub {
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

export interface DurableObjectNamespace {
  idFromName(name: string): DurableObjectId;
  get(id: DurableObjectId): DurableObjectStub;
}

export interface R2ObjectBody {
  readonly body: ReadableStream;
  readonly size: number;
  readonly httpEtag: string;
  readonly customMetadata?: Record<string, string>;
  json<T = unknown>(): Promise<T>;
  arrayBuffer(): Promise<ArrayBuffer>;
}

export interface R2Object {
  readonly size: number;
  readonly httpEtag: string;
  readonly customMetadata?: Record<string, string>;
}

export interface R2Bucket {
  put(key: string, value: string | ArrayBuffer | ArrayBufferView | ReadableStream, options?: unknown): Promise<R2Object>;
  head(key: string): Promise<R2Object | null>;
  get(key: string, options?: { range?: { offset: number; length: number } }): Promise<R2ObjectBody | null>;
  delete(key: string): Promise<void>;
}
