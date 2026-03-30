declare class DurableObject {
  constructor(state: unknown, env: unknown);
}

declare class DurableObjectState {
  storage: {
    get<T>(key: string): Promise<T | undefined>;
    put<T>(key: string, value: T): Promise<void>;
    delete(key: string): Promise<void>;
    setAlarm(epochMillis: number | Date): Promise<void>;
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
