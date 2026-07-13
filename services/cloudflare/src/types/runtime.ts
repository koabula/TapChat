export interface DurableObjectStorageLike {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  putEntries(entries: Record<string, unknown>): Promise<void>;
  mutateEntries(entries: Record<string, unknown>, deleteKeys: string[]): Promise<void>;
  delete(key: string): Promise<void>;
  list<T>(options?: { prefix?: string }): Promise<Map<string, T>>;
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
  send(payload: string): boolean;
}
