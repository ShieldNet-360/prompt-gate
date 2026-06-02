import React, { useCallback, useEffect, useRef, useState } from 'react';

export interface ToastMessage {
  id: string;
  title: string;
  body: string;
  type?: 'error' | 'warning' | 'info';
  faqUrl?: string;
}

const AUTO_DISMISS_MS = 3000;
const FADE_OUT_MS = 400;

export function ToastContainer({ toasts, onDismiss }: {
  toasts: ToastMessage[];
  onDismiss: (id: string) => void;
}) {
  const [hovered, setHovered] = useState(false);
  const timers = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  const scheduleDismiss = useCallback((id: string) => {
    if (timers.current.has(id)) return;
    const t = setTimeout(() => {
      timers.current.delete(id);
      onDismiss(id);
    }, AUTO_DISMISS_MS);
    timers.current.set(id, t);
  }, [onDismiss]);

  // Pause timers while hovered, restart when leaving
  useEffect(() => {
    if (hovered) {
      // Clear all pending timers
      timers.current.forEach((t) => clearTimeout(t));
      timers.current.clear();
    } else {
      // Restart timers for all visible toasts
      toasts.forEach((t) => scheduleDismiss(t.id));
    }
  }, [hovered, toasts, scheduleDismiss]);

  // Schedule dismiss for new toasts when not hovered
  useEffect(() => {
    if (!hovered) {
      toasts.forEach((t) => scheduleDismiss(t.id));
    }
  }, [toasts, hovered, scheduleDismiss]);

  // Clean up timers on unmount
  useEffect(() => {
    return () => {
      timers.current.forEach((t) => clearTimeout(t));
    };
  }, []);

  if (toasts.length === 0) return null;

  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        position: 'fixed',
        top: 8,
        right: 8,
        zIndex: 9999,
        width: 180,
        maxHeight: '25vh',
        overflowY: hovered ? 'auto' : 'hidden',
        overflowX: 'hidden',
        display: 'flex',
        flexDirection: 'column',
        gap: 4,
        opacity: hovered ? 1 : 0.85,
        transition: `opacity ${FADE_OUT_MS}ms ease`,
        // Thin scrollbar
        scrollbarWidth: 'thin',
      }}
    >
      {toasts.map((t) => {
        const bgColor = t.type === 'error' ? '#991b1b'
          : t.type === 'warning' ? '#92400e'
          : '#1e40af';
        return (
          <div
            key={t.id}
            style={{
              background: bgColor,
              color: '#fff',
              borderRadius: 6,
              padding: '6px 8px',
              boxShadow: '0 2px 8px rgba(0,0,0,0.2)',
              cursor: 'pointer',
              flexShrink: 0,
              animation: 'toastSlideIn 0.2s ease-out',
            }}
            onClick={() => onDismiss(t.id)}
          >
            <div style={{ fontWeight: 600, fontSize: 10, marginBottom: 1 }}>
              {t.title}
            </div>
            <div style={{ fontSize: 9, opacity: 0.9, lineHeight: 1.3 }}>
              {t.body}
            </div>
            {t.faqUrl && (
              <div
                role="link"
                tabIndex={0}
                onClick={(e) => {
                  e.stopPropagation();
                  window.secureEdge?.openExternal?.(t.faqUrl!);
                }}
                style={{
                  fontSize: 9,
                  marginTop: 3,
                  fontWeight: 600,
                  textDecoration: 'underline',
                  cursor: 'pointer',
                }}
              >
                How to send this safely →
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
