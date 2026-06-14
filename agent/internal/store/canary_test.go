package store

import (
	"context"
	"testing"
)

func TestCanaryCreateListDelete(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	c, err := s.CreateCanary(ctx, "prod_db_password_file", "PGCRYdeadbeefAAAAAAAAAAAAAAAAAAAA", 1000)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if c.ID == "" {
		t.Fatal("expected generated id")
	}
	if c.CreatedAt != 1000 {
		t.Errorf("created_at = %d, want 1000", c.CreatedAt)
	}

	list, err := s.ListCanaries(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("len(list) = %d, want 1", len(list))
	}
	if list[0].Token != "PGCRYdeadbeefAAAAAAAAAAAAAAAAAAAA" || list[0].Label != "prod_db_password_file" {
		t.Errorf("round-trip mismatch: %+v", list[0])
	}
	if list[0].TriggerCount != 0 || list[0].LastTriggered != 0 {
		t.Errorf("new canary should have zero triggers: %+v", list[0])
	}

	ok, err := s.DeleteCanary(ctx, c.ID)
	if err != nil || !ok {
		t.Fatalf("delete: ok=%v err=%v", ok, err)
	}
	list, _ = s.ListCanaries(ctx)
	if len(list) != 0 {
		t.Fatalf("len after delete = %d, want 0", len(list))
	}

	// Deleting a missing id reports false, no error.
	ok, err = s.DeleteCanary(ctx, "nope")
	if err != nil {
		t.Fatalf("delete missing: %v", err)
	}
	if ok {
		t.Error("delete of missing id should report false")
	}
}

func TestCanaryRecordTrigger(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	if _, err := s.CreateCanary(ctx, "myfile", "PGCRYaaaaaaaaBBBBBBBBBBBBBBBBBBBB", 1000); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := s.RecordCanaryTrigger(ctx, "myfile", 2000); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := s.RecordCanaryTrigger(ctx, "myfile", 3000); err != nil {
		t.Fatalf("record: %v", err)
	}

	list, _ := s.ListCanaries(ctx)
	if list[0].TriggerCount != 2 {
		t.Errorf("trigger_count = %d, want 2", list[0].TriggerCount)
	}
	if list[0].LastTriggered != 3000 {
		t.Errorf("last_triggered = %d, want 3000", list[0].LastTriggered)
	}

	// Recording against an unknown label is a no-op (not an error).
	if err := s.RecordCanaryTrigger(ctx, "ghost", 4000); err != nil {
		t.Fatalf("record unknown: %v", err)
	}
}

func TestCanaryTokenUniqueness(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	if _, err := s.CreateCanary(ctx, "a", "PGCRYsametokenXXXXXXXXXXXXXXXXXXX", 1); err != nil {
		t.Fatalf("first create: %v", err)
	}
	// Same token must violate the UNIQUE constraint.
	if _, err := s.CreateCanary(ctx, "b", "PGCRYsametokenXXXXXXXXXXXXXXXXXXX", 2); err == nil {
		t.Fatal("expected unique-constraint error on duplicate token")
	}
}
