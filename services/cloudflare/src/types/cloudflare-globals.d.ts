declare class DurableObject {
  constructor(state: unknown, env: unknown);
}

declare class DurableObjectState {
  storage: {
    get<T>(key: string): Promise<T | undefined>;
    put<T>(key: string, value: T): Promise<void>;
    delete(key: string): Promise<void>;
    list<T>(options?: { prefix?: string }): Promise<Map<string, T>>;
    setAlarm(epochMillis: number | Date): Promise<void>;
    transaction<T>(
      callback: (transaction: {
        put(values: Record<string, unknown>): Promise<void>;
        delete(keys: string[]): Promise<unknown>;
      }) => Promise<T>
    ): Promise<T>;
  };
}

declare interface WebSocket {
  accept(): void;
  send(payload: string): void;
  addEventListener(type: string, listener: () => void): void;
}

declare class WebSocketPair {
  0: WebSocket;
  1: WebSocket;
  [index: number]: WebSocket;
}
