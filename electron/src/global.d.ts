// Type augmentation for the preload bridge exposed on `window.secureEdge`.

export type PromptGateView = 'status' | 'settings' | 'proxy' | 'rules' | 'setup';

export interface AgentEvent {
  type: string;
  title: string;
  body: string;
  pattern_name?: string;
  host?: string;
  faq_url?: string;
  timestamp: string;
}

export interface PromptGateBridge {
  getAgentBase(): Promise<string>;
  getAgentToken(): Promise<string | null>;
  onNavigate(cb: (view: PromptGateView) => void): () => void;
  onEvent?(cb: (event: AgentEvent) => void): () => void;
  openExternal?(url: string): void;
  pickUpstreamCA?(): Promise<{ name: string; pem: string } | null>;
  getOpenAtLogin?(): Promise<boolean>;
  setOpenAtLogin?(enabled: boolean): Promise<boolean>;
}

declare global {
  interface Window {
    secureEdge?: PromptGateBridge;
  }
}

export {};
