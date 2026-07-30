// Upload-aware text extraction for the DLP scan path.
//
// A user can leak a secret by *uploading a file* to an LLM, not just by
// pasting it into the chat box. Those uploads arrive in shapes the plain
// request body doesn't reveal: multipart/form-data (the OpenAI / xAI /
// Anthropic Files APIs, browser attachment posts), base64-encoded blobs
// inside JSON (inline document/image data), and gzip/deflate transport
// compression. This file unwraps those layers into plain text so the
// existing DLP pipeline can scan the actual content.
//
// Scope is deliberately limited to TEXT: multipart text parts, base64
// text, and decompression. Binary document formats (PDF, zip/Office) are
// out of scope — they pass through as raw bytes and are not text-extracted.
package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// capScanText bounds the extracted text fed to the DLP pipeline. Decoding
// can expand a body well past the raw cap (a 40 MiB upload of repetitive
// text, a base64 blob), so the scanner only ever sees maxScanBytes.
func capScanText(s string) string {
	if len(s) > maxScanBytes {
		return s[:maxScanBytes]
	}
	return s
}

// decompressForScan transparently inflates a gzip/deflate body so the
// scanner sees plaintext. It is bounded by maxFileBytes (decompression-
// bomb guard) and falls back to the original bytes on any error or when
// the encoding isn't compression we handle.
func decompressForScan(enc string, body []byte) []byte {
	enc = strings.ToLower(strings.TrimSpace(enc))
	if enc == "" || enc == "identity" || len(body) == 0 {
		return body
	}
	var r io.Reader
	switch {
	case strings.Contains(enc, "gzip"), strings.Contains(enc, "x-gzip"):
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body
		}
		defer zr.Close()
		r = zr
	case strings.Contains(enc, "deflate"):
		fr := flate.NewReader(bytes.NewReader(body))
		defer fr.Close()
		r = fr
	default:
		return body
	}
	dec, err := io.ReadAll(io.LimitReader(r, maxFileBytes))
	if err != nil || len(dec) == 0 {
		return body
	}
	return dec
}

// compressRedactedBody re-compresses the redacted text matching the original
// Content-Encoding header (gzip or deflate). Returns uncompressed bytes if no
// compression was used originally.
func compressRedactedBody(enc string, redactedText string) ([]byte, error) {
	enc = strings.ToLower(strings.TrimSpace(enc))
	data := []byte(redactedText)
	if enc == "" || enc == "identity" {
		return data, nil
	}

	switch {
	case strings.Contains(enc, "gzip"), strings.Contains(enc, "x-gzip"):
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		if _, err := gw.Write(data); err != nil {
			return nil, err
		}
		if err := gw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case strings.Contains(enc, "deflate"):
		var buf bytes.Buffer
		fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
		if err != nil {
			return nil, err
		}
		if _, err := fw.Write(data); err != nil {
			return nil, err
		}
		if err := fw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	default:
		return data, nil
	}
}

// extractMultipart parses a multipart/form-data body and returns the
// filenames and text content of every part, decoding any base64-encoded
// part. Reading is bounded by maxScanBytes across all parts. Returns ""
// when the body isn't parseable multipart (the caller falls back to raw).
func extractMultipart(ct string, body []byte) string {
	_, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return ""
	}
	boundary := params["boundary"]
	if boundary == "" {
		return ""
	}

	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	var sb strings.Builder
	for {
		part, err := mr.NextRawPart()
		if err != nil {
			break // io.EOF or malformed tail — stop with what we have.
		}
		// Filenames frequently embed secrets (e.g. id_rsa, .env) and are
		// cheap to include.
		if fn := part.FileName(); fn != "" {
			appendChunk(&sb, fn)
		}
		remaining := maxScanBytes - sb.Len()
		if remaining <= 0 {
			part.Close()
			break
		}
		// Read one byte past the budget so capScanText (not a silent
		// truncation here) decides the final bound.
		data, _ := io.ReadAll(io.LimitReader(part, int64(remaining)+1))
		part.Close()
		if len(data) == 0 {
			continue
		}
		appendChunk(&sb, string(data))
		// An uploaded text file may itself be base64-encoded inside the
		// part; surface its decoded form too.
		if dec := decodeBase64Text(string(data)); dec != "" {
			appendChunk(&sb, dec)
		}
		if sb.Len() >= maxScanBytes {
			break
		}
	}
	return sb.String()
}

func appendChunk(sb *strings.Builder, s string) {
	if s == "" {
		return
	}
	if sb.Len() > 0 {
		sb.WriteByte('\n')
	}
	sb.WriteString(s)
}

// base64Run matches a run of base64 (standard or URL alphabet) long
// enough to plausibly be encoded content rather than an identifier.
var base64Run = regexp.MustCompile(`[A-Za-z0-9+/_-]{24,}={0,2}`)

// decodeBase64Text returns decoded base64 *text* found in s — either the
// whole string when s is itself one base64 blob (possibly line-wrapped),
// or the concatenation of embedded base64 runs (e.g. a JSON "data" field).
// Non-text decodings (binary, garbage) are dropped. Returns "" when there
// is no base64 text to surface.
func decodeBase64Text(s string) string {
	// The body/part is itself a single base64 blob (octet-stream upload,
	// PEM-style line wrapping). Strip whitespace and try the whole thing.
	if whole := tryBase64(stripWhitespace(s)); whole != "" {
		return whole
	}
	// Otherwise pull base64 blobs embedded in JSON/text.
	var out strings.Builder
	for _, m := range base64Run.FindAllString(s, -1) {
		dec := tryBase64(m)
		if dec == "" {
			continue
		}
		appendChunk(&out, dec)
		if out.Len() >= maxScanBytes {
			break
		}
	}
	return out.String()
}

// tryBase64 decodes m with the standard and URL alphabets (padded and
// raw) and returns the result only if it decodes cleanly to printable
// text. Anything shorter than 24 chars, or that decodes to binary, is
// rejected to avoid flooding the scanner with false content.
func tryBase64(m string) string {
	if len(m) < 24 {
		return ""
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		dec, err := enc.DecodeString(m)
		if err == nil && isTexty(dec) {
			return string(dec)
		}
	}
	return ""
}

// isTexty reports whether b looks like human-readable text: valid UTF-8
// and overwhelmingly printable characters. Used to keep binary base64
// (images, archives) out of the scan text.
func isTexty(b []byte) bool {
	if len(b) < 8 || !utf8.Valid(b) {
		return false
	}
	printable := 0
	total := 0
	for _, r := range string(b) {
		total++
		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			printable++
		}
	}
	return total > 0 && float64(printable)/float64(total) >= 0.85
}

func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
}
