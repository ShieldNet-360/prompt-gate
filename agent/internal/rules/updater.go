package rules

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Manifest is the on-disk + over-the-wire description of a rule
// bundle. The agent fetches one of these from RuleUpdateURL on every
// poll and compares it against the locally-installed version.
type Manifest struct {
	Version string         `json:"version"`
	Files   []ManifestFile `json:"files"`
}

// ManifestFile is a single rule file. Either an explicit URL or a path
// relative to the manifest's URL is accepted. SHA256 is required so the
// updater can verify each file before atomically replacing the local copy.
type ManifestFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	URL    string `json:"url,omitempty"`
}

// VersionStore is the subset of *store.Store the Updater needs.
// Keeping it as an interface lets updater_test.go drive the updater
// with an in-memory implementation.
type VersionStore interface {
	CurrentRuleVersion(ctx context.Context) (string, error)
	AppendRuleVersion(ctx context.Context, version string) error
}

// ReloadFunc is called after one or more rule files have been updated.
// Implementations typically call engine.Reload and pipeline.Rebuild.
type ReloadFunc func(ctx context.Context) error

// Options configures a new Updater.
type Options struct {
	// ManifestURL is the absolute HTTP(S) URL of manifest.json. An
	// empty value disables the updater.
	ManifestURL string

	// PollInterval defaults to 6 hours when zero.
	PollInterval time.Duration

	// RulesDir is the directory rule files are downloaded into. Each
	// ManifestFile.Name is resolved as RulesDir/Name; absolute names
	// are rejected to keep us inside the rules directory.
	RulesDir string

	// HTTPClient is the client used for manifest + file fetches. If
	// nil, a default *http.Client with a 30s timeout is used.
	HTTPClient *http.Client

	// Store is used to record the current manifest version. May be nil
	// when version persistence is not required (e.g. tests).
	Store VersionStore

	// Reload is invoked after any file was replaced. May be nil.
	Reload ReloadFunc

	// Now returns the current time; injected for tests. Defaults to time.Now.
	Now func() time.Time

	// PublicKey is the Ed25519 public key used to verify the manifest
	// signature (SE-03). When non-nil, fetchManifest requires a valid
	// X-Signature header on the response. When nil, signature
	// verification is skipped (for backward compatibility / tests).
	PublicKey ed25519.PublicKey
}

// DefaultPollInterval is the polling cadence used when Options.PollInterval is zero.
const DefaultPollInterval = 6 * time.Hour

// Updater periodically fetches a manifest and applies delta updates to
// the locally-installed rule files. Safe for concurrent use.
type Updater struct {
	opts Options

	mu             sync.RWMutex
	currentVersion string
	lastCheck      time.Time
	nextCheck      time.Time
}

// New constructs an Updater. Returns an error when ManifestURL is empty
// or RulesDir is empty / not a directory.
func New(opts Options) (*Updater, error) {
	if strings.TrimSpace(opts.ManifestURL) == "" {
		return nil, errors.New("updater: ManifestURL is required")
	}
	// SE-03: Enforce HTTPS to prevent manifest tampering via MitM.
	if mu, err := url.Parse(opts.ManifestURL); err != nil {
		return nil, fmt.Errorf("updater: invalid ManifestURL: %w", err)
	} else if mu.Scheme != "https" {
		return nil, fmt.Errorf("updater: ManifestURL scheme %q must be https", mu.Scheme)
	}
	if strings.TrimSpace(opts.RulesDir) == "" {
		return nil, errors.New("updater: RulesDir is required")
	}
	if opts.PollInterval == 0 {
		opts.PollInterval = DefaultPollInterval
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Updater{opts: opts}, nil
}

// Status is a snapshot of the updater's bookkeeping fields. Returned by
// the GET /api/rules/status handler.
type Status struct {
	CurrentVersion string    `json:"current_version"`
	LastCheck      time.Time `json:"last_check"`
	NextCheck      time.Time `json:"next_check"`
	UpdateURL      string    `json:"update_url"`
}

// Status returns a snapshot of the updater's bookkeeping fields.
func (u *Updater) Status() Status {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return Status{
		CurrentVersion: u.currentVersion,
		LastCheck:      u.lastCheck,
		NextCheck:      u.nextCheck,
		UpdateURL:      u.opts.ManifestURL,
	}
}

// Result describes the outcome of one update cycle.
type Result struct {
	Updated         bool   `json:"updated"`
	Version         string `json:"version"`
	FilesDownloaded int    `json:"files_downloaded"`
}

// Start runs CheckNow on ctx's goroutine immediately, then again on
// every PollInterval until ctx is cancelled.
func (u *Updater) Start(ctx context.Context) {
	// One eager check at startup so a manifest update that landed
	// while the agent was down is applied without waiting a full
	// poll interval.
	if _, err := u.CheckNow(ctx); err != nil {
		// Log to stderr — we don't want to wedge agent startup on
		// transient network errors.
		fmt.Fprintf(os.Stderr, "rule updater: initial check failed: %v\n", err)
	}
	ticker := time.NewTicker(u.opts.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := u.CheckNow(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "rule updater: check failed: %v\n", err)
			}
		}
	}
}

// CheckNow runs one update cycle. It is safe to call concurrently —
// the lock around the bookkeeping fields prevents torn reads from
// Status, and the filesystem writes use os.Rename for atomic
// replacement so a concurrent reader of the rule files always sees a
// consistent version.
func (u *Updater) CheckNow(ctx context.Context) (Result, error) {
	now := u.opts.Now()
	u.mu.Lock()
	u.lastCheck = now
	u.nextCheck = now.Add(u.opts.PollInterval)
	current := u.currentVersion
	if current == "" && u.opts.Store != nil {
		// Prefer the persisted value on first call after restart.
		if v, err := u.opts.Store.CurrentRuleVersion(ctx); err == nil {
			u.currentVersion = v
			current = v
		}
	}
	u.mu.Unlock()

	manifest, err := u.fetchManifest(ctx)
	if err != nil {
		return Result{}, err
	}

	count, err := u.applyManifest(ctx, manifest)
	if err != nil {
		return Result{}, err
	}

	versionChanged := manifest.Version != current

	// Reload the live engines *before* recording the new version in
	// memory or in the store. If the reload fails — bad pattern in
	// the new file, syntax error in a rules list, etc — `current`
	// stays pointing at the old version so the next poll will retry
	// the reload (versionChanged will still be true even though all
	// downloaded files match SHAs on disk). Persisting the new
	// version up front would mark the cycle "successful", leave the
	// engine running on the previous rule set, and skip the reload
	// indefinitely (until the manifest version bumps again).
	needsReload := (count > 0 || versionChanged) && u.opts.Reload != nil
	if needsReload {
		if err := u.opts.Reload(ctx); err != nil {
			return Result{}, fmt.Errorf("reload: %w", err)
		}
	}

	u.mu.Lock()
	u.currentVersion = manifest.Version
	u.mu.Unlock()

	if versionChanged && u.opts.Store != nil {
		if err := u.opts.Store.AppendRuleVersion(ctx, manifest.Version); err != nil {
			return Result{}, fmt.Errorf("persist version: %w", err)
		}
	}

	return Result{
		Updated:         count > 0 || versionChanged,
		Version:         manifest.Version,
		FilesDownloaded: count,
	}, nil
}

// fetchManifest issues GET ManifestURL, optionally verifies the
// Ed25519 signature (SE-03), and decodes the response.
func (u *Updater) fetchManifest(ctx context.Context) (Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.opts.ManifestURL, nil)
	if err != nil {
		return Manifest{}, fmt.Errorf("manifest request: %w", err)
	}
	resp, err := u.opts.HTTPClient.Do(req)
	if err != nil {
		return Manifest{}, fmt.Errorf("manifest fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Manifest{}, fmt.Errorf("manifest fetch: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return Manifest{}, fmt.Errorf("manifest read: %w", err)
	}

	// SE-03: Verify Ed25519 signature when a public key is configured.
	if len(u.opts.PublicKey) > 0 {
		sigHex := resp.Header.Get("X-Signature")
		if sigHex == "" {
			return Manifest{}, errors.New("manifest: missing X-Signature header")
		}
		sig, err := hex.DecodeString(sigHex)
		if err != nil {
			return Manifest{}, fmt.Errorf("manifest: invalid X-Signature encoding: %w", err)
		}
		if !ed25519.Verify(u.opts.PublicKey, body, sig) {
			return Manifest{}, errors.New("manifest: Ed25519 signature verification failed")
		}
	}

	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return Manifest{}, fmt.Errorf("manifest decode: %w", err)
	}
	if strings.TrimSpace(m.Version) == "" {
		return Manifest{}, errors.New("manifest: empty version")
	}
	if len(m.Files) == 0 {
		return Manifest{}, errors.New("manifest: no files")
	}
	return m, nil
}

// applyManifest iterates manifest.Files, compares each against the
// locally-installed file's SHA256, downloads any mismatches, and
// atomically replaces the local copy. Returns the number of files that
// were actually downloaded + replaced.
func (u *Updater) applyManifest(ctx context.Context, m Manifest) (int, error) {
	if err := os.MkdirAll(u.opts.RulesDir, 0o755); err != nil {
		return 0, fmt.Errorf("rules dir: %w", err)
	}

	count := 0
	for _, f := range m.Files {
		// Defence in depth: reject any path traversal in the manifest.
		if f.Name == "" || strings.ContainsAny(f.Name, "/\\") || f.Name == ".." || strings.HasPrefix(f.Name, ".") {
			return count, fmt.Errorf("rule %q: invalid name", f.Name)
		}
		if len(f.SHA256) != 64 {
			return count, fmt.Errorf("rule %q: invalid sha256", f.Name)
		}

		dest := filepath.Join(u.opts.RulesDir, f.Name)
		existing, err := fileSHA256(dest)
		if err == nil && strings.EqualFold(existing, f.SHA256) {
			continue // delta: file unchanged, skip download
		}

		fileURL, err := u.resolveFileURL(f)
		if err != nil {
			return count, fmt.Errorf("rule %q: %w", f.Name, err)
		}

		if err := u.downloadAndReplace(ctx, fileURL, dest, f.SHA256); err != nil {
			return count, fmt.Errorf("rule %q: %w", f.Name, err)
		}
		count++
	}
	return count, nil
}

// resolveFileURL returns the absolute URL for a ManifestFile. An
// explicit URL wins; otherwise the file's URL is interpreted as
// "manifest.json's parent directory + file Name", which lets a host
// serve a flat directory of rules without listing each URL.
func (u *Updater) resolveFileURL(f ManifestFile) (string, error) {
	if f.URL != "" {
		return f.URL, nil
	}
	base, err := url.Parse(u.opts.ManifestURL)
	if err != nil {
		return "", fmt.Errorf("parse manifest URL: %w", err)
	}
	ref, err := base.Parse(f.Name)
	if err != nil {
		return "", fmt.Errorf("resolve rule URL: %w", err)
	}
	return ref.String(), nil
}

// downloadAndReplace fetches src, writes it to a temp file in the
// destination's directory, verifies its SHA256 matches wantHex, and
// only then renames the temp file over the destination. A mismatched
// or short download leaves the existing file untouched.
func (u *Updater) downloadAndReplace(ctx context.Context, src, dst, wantHex string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return fmt.Errorf("download request: %w", err)
	}
	resp, err := u.opts.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("download fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}

	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".rule-*.tmp")
	if err != nil {
		return fmt.Errorf("temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op when Rename succeeds

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, 16*1024*1024)); err != nil {
		tmp.Close()
		return fmt.Errorf("download copy: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("temp close: %w", err)
	}

	gotHex := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(gotHex, wantHex) {
		return fmt.Errorf("sha256 mismatch: want %s got %s", wantHex, gotHex)
	}

	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("atomic rename: %w", err)
	}
	return nil
}

// fileSHA256 returns the lower-case hex SHA256 of the file at path, or
// "" + os.ErrNotExist when the file is missing.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
