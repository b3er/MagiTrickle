package records

import (
	"testing"
	"time"
)

func TestAddAndGetPTRRecord(t *testing.T) {
	r := New()
	ptrName := "1.0.0.127.in-addr.arpa."
	hostname := "localhost."
	ttl := uint32(300)

	// Add PTR record
	r.AddPTRRecord(ptrName, hostname, ttl)

	// Verify record was stored
	record := r.GetPTRRecord(ptrName)
	if record == nil {
		t.Fatal("PTR record not found after adding")
	}
	if record.Hostname != hostname {
		t.Fatalf("Expected hostname %s, got %s", hostname, record.Hostname)
	}
}

func TestPTRRecordNormalization(t *testing.T) {
	r := New()
	ptrName := "1.0.0.127.in-addr.arpa."
	normalizedName := "1.0.0.127.in-addr.arpa" // Without trailing dot
	hostname := "localhost."
	ttl := uint32(300)

	// Add PTR record with trailing dot
	r.AddPTRRecord(ptrName, hostname, ttl)

	// Verify record can be found with normalized name (without trailing dot)
	record := r.GetPTRRecord(normalizedName)
	if record == nil {
		t.Fatal("PTR record not found with normalized name")
	}
	if record.Hostname != hostname {
		t.Fatalf("Expected hostname %s, got %s", hostname, record.Hostname)
	}

	// Also verify the reverse - add with normalized, retrieve with dot
	r = New()
	r.AddPTRRecord(normalizedName, hostname, ttl)
	record = r.GetPTRRecord(ptrName)
	if record == nil {
		t.Fatal("PTR record not found with trailing dot")
	}
}

func TestPTRRecordExpiration(t *testing.T) {
	r := New()
	ptrName := "1.0.0.127.in-addr.arpa."
	hostname := "localhost."

	// Add PTR record with very short TTL (1 second)
	r.AddPTRRecord(ptrName, hostname, 1)

	// Verify record exists immediately
	if r.GetPTRRecord(ptrName) == nil {
		t.Fatal("PTR record should exist immediately after adding")
	}

	// Wait for TTL to expire
	time.Sleep(2 * time.Second)

	// Record should now be expired and not returned
	if record := r.GetPTRRecord(ptrName); record != nil {
		t.Fatal("PTR record should have been expired")
	}
}

func TestEmptyPTRRecord(t *testing.T) {
	r := New()
	ptrName := "1.0.0.127.in-addr.arpa."

	// Add empty PTR record (represents negative cache)
	r.AddPTRRecord(ptrName, "", 300)

	// Verify record exists
	record := r.GetPTRRecord(ptrName)
	if record == nil {
		t.Fatal("Empty PTR record not found")
	}

	// Verify hostname is empty
	if record.Hostname != "" {
		t.Fatalf("Expected empty hostname, got %s", record.Hostname)
	}
}

func TestPTRCleanupOnGet(t *testing.T) {
	r := New()
	ptrName1 := "1.0.0.127.in-addr.arpa."
	ptrName2 := "2.0.0.127.in-addr.arpa."
	hostname := "localhost."

	// Add one record with very short TTL
	r.AddPTRRecord(ptrName1, hostname, 1)

	// Add another record with longer TTL
	r.AddPTRRecord(ptrName2, hostname, 300)

	// Wait for first record to expire
	time.Sleep(2 * time.Second)

	// Getting any record should trigger cleanup of expired records
	r.GetPTRRecord(ptrName2)

	// Check if record1 was cleaned up
	if r.GetPTRRecord(ptrName1) != nil {
		t.Fatal("Expired PTR record should have been cleaned up")
	}

	// Record2 should still exist
	if r.GetPTRRecord(ptrName2) == nil {
		t.Fatal("Valid PTR record should still exist")
	}
}

func TestMultiplePTRRecords(t *testing.T) {
	r := New()

	// Add multiple PTR records
	records := []struct {
		name     string
		hostname string
		ttl      uint32
	}{
		{"1.0.0.127.in-addr.arpa.", "localhost.", 300},
		{"1.1.168.192.in-addr.arpa.", "router.local.", 300},
		{"42.42.42.42.in-addr.arpa.", "example.com.", 300},
	}

	for _, rec := range records {
		r.AddPTRRecord(rec.name, rec.hostname, rec.ttl)
	}

	// Verify all records can be retrieved
	for _, rec := range records {
		ptr := r.GetPTRRecord(rec.name)
		if ptr == nil {
			t.Fatalf("PTR record for %s not found", rec.name)
		}
		if ptr.Hostname != rec.hostname {
			t.Fatalf("For %s expected hostname %s, got %s", rec.name, rec.hostname, ptr.Hostname)
		}
	}
}
