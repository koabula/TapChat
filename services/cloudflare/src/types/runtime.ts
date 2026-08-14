export interface DurableObjectStorageLike {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  putEntries(entries: Record<string, unknown>): Promise<void>;
  mutateEntries(entries: Record<string, unknown>, deleteKeys: string[]): Promise<void>;
  delete(key: string): Promise<void>;
  list<T>(options?: { prefix?: string }): Promise<Map<string, T>>;
  setAlarm(epochMillis: number): Promise<void>;
  consumeIfEqual?<T>(key: string, expected: T): Promise<boolean>;
}

export interface JsonBlobStore {
  putJson<T>(key: string, value: T): Promise<void>;
  getJson<T>(key: string): Promise<T | null>;
  putBytes(key: string, value: ArrayBuffer | Uint8Array, metadata?: Record<string, string>): Promise<void>;
  getBytes(key: string): Promise<ArrayBuffer | null>;
  getBytesMetadata?(key: string): Promise<{ bytes: ArrayBuffer; customMetadata: Record<string, string> } | null>;
  delete(key: string): Promise<void>;
}

export interface BlobByteRange {
  offset: number;
  length: number;
}

export interface BinaryBlobMetadata {
  size: number;
  customMetadata: Record<string, string>;
  httpEtag?: string;
}

export interface BinaryBlobBody extends BinaryBlobMetadata {
  body: ReadableStream;
}

export interface BinaryBlobStore {
  putStream(
    key: string,
    value: ReadableStream,
    metadata?: Record<string, string>,
  ): Promise<{ size: number }>;
  headBytes(key: string): Promise<BinaryBlobMetadata | null>;
  getStream(key: string, range?: BlobByteRange): Promise<BinaryBlobBody | null>;
  delete(key: string): Promise<void>;
}

export interface SessionSink {
  send(payload: string): boolean;
}
