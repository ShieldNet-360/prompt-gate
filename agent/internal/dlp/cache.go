// Short-lived scan-result cache (Phase 6 Task 9).
//
// The cache lives entirely in-memory and is keyed on a SHA-256 of the
// scanned content. The hash is the only thing we keep — the original
// content never crosses any boundary that could persist it. Entries
// expire after ScanCacheTTL (5s by default) so a pattern or config
// update is reflected almost immediately on the next scan.
//
// Privacy invariant: we MUST NOT store content, snippets, or pattern
// metadata that could reveal what the user pasted. The cache only
// retains anonymous (digest, ScanResult, expires_at) tuples.

package dlp

import (
	"container/list"
	"crypto/sha256"
	"sync"
	"time"
)

// ScanCacheTTL is the default lifetime of a cache entry. Five seconds
// is short enough that operators do not need to manually invalidate
// the cache after a rule update and long enough to deduplicate the
// rapid-fire scans that hit the agent when an extension's paste,
// form-submit, and fetch interceptors all fire on the same content.
const ScanCacheTTL = 5 * time.Second

// ScanCacheCapacity bounds the number of entries the LRU holds. Each
// entry is small (32-byte digest + ScanResult + a doubly-linked list
// node) so the default of 1024 fits comfortably in a few hundred KiB.
const ScanCacheCapacity = 1024

// scanCacheEntry is the stored value inside the LRU node.
type scanCacheEntry struct {
	digest   [sha256.Size]byte
	result   ScanResult
	inserted time.Time
}

// ScanCache is a small fixed-size LRU keyed on SHA-256 of the scanned
// content. It is safe for concurrent use.
type ScanCache struct {
	mu        sync.Mutex
	capacity  int
	ttl       time.Duration
	now       func() time.Time
	items     map[[sha256.Size]byte]*list.Element
	order     *list.List // front = most-recently used
	hits      uint64
	misses    uint64
	evictions uint64
}

// NewScanCache constructs an LRU cache with the supplied capacity and
// TTL. Zero or negative values fall back to ScanCacheCapacity /
// ScanCacheTTL respectively.
func NewScanCache(capacity int, ttl time.Duration) *ScanCache {
	if capacity <= 0 {
		capacity = ScanCacheCapacity
	}
	if ttl <= 0 {
		ttl = ScanCacheTTL
	}
	return &ScanCache{
		capacity: capacity,
		ttl:      ttl,
		now:      time.Now,
		items:    make(map[[sha256.Size]byte]*list.Element, capacity),
		order:    list.New(),
	}
}

// Lookup returns the cached ScanResult for content, or (zero, false)
// on a miss or stale entry. A stale entry is also evicted as a side
// effect so subsequent Lookup calls return a miss until the next Put.
func (c *ScanCache) Lookup(content string) (ScanResult, bool) {
	if c == nil {
		return ScanResult{}, false
	}
	digest := sha256.Sum256([]byte(content))
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[digest]
	if !ok {
		c.misses++
		return ScanResult{}, false
	}
	entry := el.Value.(*scanCacheEntry)
	if c.now().Sub(entry.inserted) > c.ttl {
		c.order.Remove(el)
		delete(c.items, digest)
		c.misses++
		return ScanResult{}, false
	}
	c.order.MoveToFront(el)
	c.hits++
	return entry.result, true
}

// Put stores the ScanResult for content. If the cache is at capacity
// the oldest entry is evicted. Putting an existing digest refreshes
// its TTL and moves it to the front of the LRU.
func (c *ScanCache) Put(content string, result ScanResult) {
	if c == nil {
		return
	}
	digest := sha256.Sum256([]byte(content))
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[digest]; ok {
		entry := el.Value.(*scanCacheEntry)
		entry.result = result
		entry.inserted = c.now()
		c.order.MoveToFront(el)
		return
	}
	entry := &scanCacheEntry{digest: digest, result: result, inserted: c.now()}
	el := c.order.PushFront(entry)
	c.items[digest] = el
	if c.order.Len() > c.capacity {
		oldest := c.order.Back()
		if oldest != nil {
			old := oldest.Value.(*scanCacheEntry)
			c.order.Remove(oldest)
			delete(c.items, old.digest)
			c.evictions++
		}
	}
}

// Stats returns anonymous counters used by /api/status. They are
// intentionally not exposed per-entry — the agent must never reveal
// which content was scanned.
type ScanCacheStats struct {
	Size      int    `json:"size"`
	Capacity  int    `json:"capacity"`
	Hits      uint64 `json:"hits"`
	Misses    uint64 `json:"misses"`
	Evictions uint64 `json:"evictions"`
}

// Stats returns a snapshot of the cache counters.
func (c *ScanCache) Stats() ScanCacheStats {
	if c == nil {
		return ScanCacheStats{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return ScanCacheStats{
		Size:      c.order.Len(),
		Capacity:  c.capacity,
		Hits:      c.hits,
		Misses:    c.misses,
		Evictions: c.evictions,
	}
}

// Reset drops every cached entry. Used by tests and on rule reload.
func (c *ScanCache) Reset() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make(map[[sha256.Size]byte]*list.Element, c.capacity)
	c.order = list.New()
	c.hits, c.misses, c.evictions = 0, 0, 0
}
