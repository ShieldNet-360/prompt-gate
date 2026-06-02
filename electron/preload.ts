// Secure bridge between the renderer and the main process. Only the
// minimum surface the renderer needs is exposed.

import { contextBridge, ipcRenderer } from 'electron';

export type PromptGateView = 'status' | 'settings' | 'proxy';

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
  onEvent(cb: (event: AgentEvent) => void): () => void;
  openExternal(url: string): void;
}

const bridge: PromptGateBridge = {
  getAgentBase: () => ipcRenderer.invoke('prompt-gate:get-agent-base'),
  getAgentToken: () => ipcRenderer.invoke('prompt-gate:get-agent-token'),
  onNavigate: (cb) => {
    const listener = (_event: unknown, view: PromptGateView) => cb(view);
    ipcRenderer.on('navigate', listener);
    return () => ipcRenderer.removeListener('navigate', listener);
  },
  onEvent: (cb) => {
    const listener = (_event: unknown, evt: AgentEvent) => cb(evt);
    ipcRenderer.on('prompt-gate:event', listener);
    return () => ipcRenderer.removeListener('prompt-gate:event', listener);
  },
  openExternal: (url) => {
    void ipcRenderer.invoke('prompt-gate:open-external', url);
  },
};

contextBridge.exposeInMainWorld('secureEdge', bridge);

declare global {
  interface Window {
    secureEdge: PromptGateBridge;
  }
}
