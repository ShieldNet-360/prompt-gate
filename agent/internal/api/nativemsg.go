package api

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/store"
)

// MaxNativeMessageBytes caps both incoming and outgoing Native Messaging
// payloads. Chrome enforces a 1 MiB limit on messages from the extension
// to the host; we mirror that so we never silently truncate.
const MaxNativeMessageBytes uint32 = 1 * 1024 * 1024

// NativeMessageRequest is the wire shape received from a connected
// Chrome extension on stdin. The id is echoed back so the extension can
// correlate concurrent requests.
type NativeMessageRequest struct {
	ID      int    `json:"id"`
	Kind    string `json:"kind"`
	Content string `json:"content"`
}

// NativeMessageResponse is the wire shape returned on stdout. Either
// Result or Error is populated, never both.
type NativeMessageResponse struct {
	ID     int             `json:"id"`
	Result *dlp.ScanResult `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// ServeNativeMessaging reads length-prefixed JSON messages from in,
// dispatches scan requests through scanner, and writes JSON responses
// to out. It returns when in is closed (io.EOF), ctx is cancelled, or
// a write fails. The function is intentionally synchronous: Chrome's
// Native Messaging protocol is a half-duplex stream and the agent
// invokes Scan() before reading the next request.
//
// statsStore, when non-nil, receives bumpDLPStats() calls after every
// successful scan so that the Status page's dlp_scans_total and
// dlp_blocks_total stay correct in NM mode. Pass nil in tests that
// don't care about counters; HTTP-only deployments are unaffected.
func ServeNativeMessaging(ctx context.Context, scanner DLPScanner, statsStore *store.Store, in io.Reader, out io.Writer) error {
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		raw, err := readNativeMessage(in, MaxNativeMessageBytes)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return fmt.Errorf("native: read: %w", err)
		}

		var req NativeMessageRequest
		resp := NativeMessageResponse{}
		if jerr := json.Unmarshal(raw, &req); jerr != nil {
			// Best-effort error reply when we can't even parse the
			// envelope. id is left at zero — the extension treats
			// id=0 as "unsolicited" and surfaces the error to the user.
			resp.Error = "invalid request JSON"
		} else {
			resp.ID = req.ID
			switch req.Kind {
			case "scan":
				if scanner == nil {
					resp.Error = "DLP pipeline not configured"
				} else {
					r := scanner.Scan(ctx, req.Content)
					req.Content = "" // drop reference promptly.
					resp.Result = &r
					// Mirror the HTTP scan handler: anonymous
					// aggregate counters must move whichever
					// transport the extension picked. Errors
					// are intentionally swallowed — counter
					// hiccups must never break a scan reply.
					_ = bumpDLPStats(ctx, statsStore, r.Blocked)
				}
			default:
				resp.Error = fmt.Sprintf("unknown kind: %q", req.Kind)
			}
		}

		if werr := writeNativeMessage(out, resp); werr != nil {
			return fmt.Errorf("native: write: %w", werr)
		}
	}
}

// readNativeMessage reads one length-prefixed JSON frame from r. The
// length prefix is 4 bytes, little-endian, matching Chrome's protocol.
func readNativeMessage(r io.Reader, max uint32) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(lenBuf[:])
	if n == 0 {
		return nil, fmt.Errorf("native: zero-length message")
	}
	if n > max {
		return nil, fmt.Errorf("native: message too large (%d > %d)", n, max)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// writeNativeMessage encodes payload as JSON and writes a 4-byte
// little-endian length prefix followed by the JSON body.
func writeNativeMessage(w io.Writer, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if uint32(len(data)) > MaxNativeMessageBytes {
		return fmt.Errorf("native: response too large (%d bytes)", len(data))
	}
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
