package stats

import (
	"context"
	"errors"
	"sync"
	"testing"
)

type fakeStore struct {
	mu        sync.Mutex
	persisted Snapshot
	failAdd   bool
}

func (f *fakeStore) GetStats(_ context.Context) (Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.persisted, nil
}

func (f *fakeStore) AddStats(_ context.Context, delta Snapshot) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failAdd {
		return errors.New("inject")
	}
	f.persisted.DNSQueriesTotal += delta.DNSQueriesTotal
	f.persisted.DNSBlocksTotal += delta.DNSBlocksTotal
	f.persisted.DLPScansTotal += delta.DLPScansTotal
	f.persisted.DLPBlocksTotal += delta.DLPBlocksTotal
	return nil
}

func (f *fakeStore) ResetStats(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.persisted = Snapshot{}
	return nil
}

func TestCounterIncrementAndSnapshot(t *testing.T) {
	c := New(&fakeStore{})
	c.IncrementDNSQueries()
	c.IncrementDNSQueries()
	c.IncrementDNSBlocks()
	c.IncrementDLPScans()
	c.IncrementDLPBlocks()
	c.IncrementDLPBlocks()

	got := c.MemorySnapshot()
	want := Snapshot{DNSQueriesTotal: 2, DNSBlocksTotal: 1, DLPScansTotal: 1, DLPBlocksTotal: 2}
	if got != want {
		t.Fatalf("snapshot = %+v, want %+v", got, want)
	}
}

func TestFlushResetsMemoryAndAdds(t *testing.T) {
	store := &fakeStore{}
	c := New(store)
	c.IncrementDNSQueries()
	c.IncrementDNSBlocks()
	c.IncrementDLPBlocks()

	if err := c.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := c.MemorySnapshot(); got != (Snapshot{}) {
		t.Fatalf("memory not zero after flush: %+v", got)
	}
	want := Snapshot{DNSQueriesTotal: 1, DNSBlocksTotal: 1, DLPBlocksTotal: 1}
	if store.persisted != want {
		t.Fatalf("persisted = %+v, want %+v", store.persisted, want)
	}
}

func TestFlushRestoresOnStoreError(t *testing.T) {
	store := &fakeStore{failAdd: true}
	c := New(store)
	c.IncrementDNSQueries()
	c.IncrementDNSQueries()
	if err := c.Flush(context.Background()); err == nil {
		t.Fatal("Flush: expected error")
	}
	if got := c.MemorySnapshot(); got.DNSQueriesTotal != 2 {
		t.Fatalf("memory after failed flush: %+v", got)
	}
}

func TestGetStatsCombinesPersistedAndMemory(t *testing.T) {
	store := &fakeStore{persisted: Snapshot{DNSQueriesTotal: 10}}
	c := New(store)
	c.IncrementDNSQueries()
	c.IncrementDNSBlocks()

	got, err := c.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	want := Snapshot{DNSQueriesTotal: 11, DNSBlocksTotal: 1}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestResetZeroesEverything(t *testing.T) {
	store := &fakeStore{persisted: Snapshot{DNSQueriesTotal: 99}}
	c := New(store)
	c.IncrementDNSQueries()
	if err := c.Reset(context.Background()); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if store.persisted != (Snapshot{}) {
		t.Fatalf("store not zero: %+v", store.persisted)
	}
	if got := c.MemorySnapshot(); got != (Snapshot{}) {
		t.Fatalf("memory not zero: %+v", got)
	}
}

func TestConcurrentIncrement(t *testing.T) {
	c := New(&fakeStore{})
	var wg sync.WaitGroup
	const goroutines = 50
	const each = 200
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				c.IncrementDNSQueries()
				c.IncrementDNSBlocks()
			}
		}()
	}
	wg.Wait()
	got := c.MemorySnapshot()
	if got.DNSQueriesTotal != goroutines*each || got.DNSBlocksTotal != goroutines*each {
		t.Fatalf("concurrent counts wrong: %+v", got)
	}
}
