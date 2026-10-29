import { BackendMessage, ReplayControlMessage } from '../../../shared/types';
import { useGraphStore } from './graphStore';

export interface SocketOptions {
  url?: string;
  maxReconnectIntervalMs?: number;
  initialReconnectIntervalMs?: number;
  backoffMultiplier?: number;
}

export class BreachSocketClient {
  private ws: WebSocket | null = null;
  private url: string;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private currentReconnectInterval: number;
  private maxReconnectInterval: number;
  private backoffMultiplier: number;
  private isManuallyClosed: boolean = false;
  private initialReconnectIntervalMs: number;

  constructor(options?: SocketOptions) {
    const defaultProto =
      typeof window !== 'undefined' && window.location.protocol === 'https:'
        ? 'wss'
        : 'ws';
    const defaultHost =
      typeof window !== 'undefined' && window.location.hostname
        ? window.location.hostname
        : 'localhost';
    this.url = options?.url ?? `${defaultProto}://${defaultHost}:8000/ws`;
    this.initialReconnectIntervalMs = options?.initialReconnectIntervalMs ?? 1000;
    this.currentReconnectInterval = this.initialReconnectIntervalMs;
    this.maxReconnectInterval = options?.maxReconnectIntervalMs ?? 10000;
    this.backoffMultiplier = options?.backoffMultiplier ?? 1.5;
  }

  public connect(url?: string): void {
    if (url) {
      this.url = url;
    }
    this.isManuallyClosed = false;

    if (
      this.ws &&
      (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)
    ) {
      return;
    }

    useGraphStore.getState().setConnectionState('connecting');

    try {
      this.ws = new WebSocket(this.url);

      this.ws.onopen = () => {
        useGraphStore.getState().setConnectionState('connected');
        this.currentReconnectInterval = this.initialReconnectIntervalMs;
      };

      this.ws.onmessage = (event: MessageEvent) => {
        try {
          useGraphStore.getState().appendWireLog(event.data);
          const message: BackendMessage = JSON.parse(event.data);
          if (message.kind === 'snapshot') {
            useGraphStore.getState().applySnapshot(message.graph);
          } else if (message.kind === 'event') {
            useGraphStore.getState().applyEvent(message.event);
          }
        } catch (err) {
          console.error('[BreachSocket] Failed to parse message:', err, event.data);
        }
      };

      this.ws.onclose = () => {
        useGraphStore.getState().setConnectionState('disconnected');
        this.ws = null;
        if (!this.isManuallyClosed) {
          this.scheduleReconnect();
        }
      };

      this.ws.onerror = () => {
        useGraphStore.getState().setConnectionState('error');
      };
    } catch (err) {
      useGraphStore.getState().setConnectionState('error');
      if (!this.isManuallyClosed) {
        this.scheduleReconnect();
      }
    }
  }

  public disconnect(): void {
    this.isManuallyClosed = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    useGraphStore.getState().setConnectionState('disconnected');
  }

  public sendReplayControl(
    action: 'start' | 'pause' | 'reset',
    speed?: number,
    entry?: string
  ): boolean {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      console.warn('[BreachSocket] Cannot send replay control: socket not open');
      return false;
    }

    const payload: ReplayControlMessage & { entry?: string } = {
      kind: 'replay_control',
      action,
      speed,
      ...(entry ? { entry } : {}),
    };

    this.ws.send(JSON.stringify(payload));
    return true;
  }

  public sendRaw(msg: any): boolean {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      return false;
    }
    this.ws.send(typeof msg === 'string' ? msg : JSON.stringify(msg));
    return true;
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, this.currentReconnectInterval);

    this.currentReconnectInterval = Math.min(
      this.currentReconnectInterval * this.backoffMultiplier,
      this.maxReconnectInterval
    );
  }
}

let globalSocketClient: BreachSocketClient | null = null;

export function getSocketClient(): BreachSocketClient {
  if (!globalSocketClient) {
    globalSocketClient = new BreachSocketClient();
  }
  return globalSocketClient;
}

export const socketClient = getSocketClient();
