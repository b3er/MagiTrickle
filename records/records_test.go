package records

import (
	"bytes"
	"slices"
	"testing"
	"time"
)

func TestLoop(t *testing.T) {
	r := New()
	r.AddCNameRecord("1", "2", time.Minute)
	r.AddCNameRecord("2", "1", time.Minute)
	if r.GetARecords("1") != nil {
		t.Fatal("loop detected")
	}
	if r.GetARecords("2") != nil {
		t.Fatal("loop detected")
	}
}

func TestCName(t *testing.T) {
	r := New()
	r.AddARecord("example.com", []byte{1, 2, 3, 4}, time.Minute)
	r.AddCNameRecord("gateway.example.com", "example.com", time.Minute)
	records := r.GetARecords("gateway.example.com")
	if records == nil {
		t.Fatal("no records")
	}
	if bytes.Compare(records[0].Address, []byte{1, 2, 3, 4}) != 0 {
		t.Fatal("cname mismatch")
	}
}

func TestA(t *testing.T) {
	r := New()
	r.AddARecord("example.com", []byte{1, 2, 3, 4}, time.Minute)
	records := r.GetARecords("example.com")
	if records == nil {
		t.Fatal("no records")
	}
	if bytes.Compare(records[0].Address, []byte{1, 2, 3, 4}) != 0 {
		t.Fatal("cname mismatch")
	}
}

func TestDeprecated(t *testing.T) {
	r := New()
	r.AddARecord("example.com", []byte{1, 2, 3, 4}, -time.Minute)
	records := r.GetARecords("example.com")
	if records != nil {
		t.Fatal("deprecated records")
	}
}

func TestNotExistedA(t *testing.T) {
	r := New()
	records := r.GetARecords("example.com")
	if records != nil {
		t.Fatal("not existed records")
	}
}

func TestNotExistedCNameAlias(t *testing.T) {
	r := New()
	r.AddCNameRecord("gateway.example.com", "example.com", time.Minute)
	records := r.GetARecords("gateway.example.com")
	if records != nil {
		t.Fatal("not existed records")
	}
}

func TestReplacing(t *testing.T) {
	r := New()
	r.AddCNameRecord("gateway.example.com", "example.com", time.Minute)
	r.AddARecord("gateway.example.com", []byte{1, 2, 3, 4}, time.Minute)
	records := r.GetARecords("gateway.example.com")
	if bytes.Compare(records[0].Address, []byte{1, 2, 3, 4}) != 0 {
		t.Fatal("mismatch")
	}
}

func TestAliases(t *testing.T) {
	r := New()
	r.AddARecord("1", []byte{1, 2, 3, 4}, time.Minute)
	r.AddCNameRecord("2", "1", time.Minute)
	r.AddCNameRecord("3", "2", time.Minute)
	r.AddCNameRecord("4", "2", time.Minute)
	r.AddCNameRecord("5", "1", time.Minute)
	aliases := r.GetAliases("1")
	if aliases == nil {
		t.Fatal("no aliases")
	}
	if !slices.Contains(aliases, "1") {
		t.Fatal("no 1")
	}
	if !slices.Contains(aliases, "2") {
		t.Fatal("no 2")
	}
	if !slices.Contains(aliases, "3") {
		t.Fatal("no 3")
	}
	if !slices.Contains(aliases, "4") {
		t.Fatal("no 4")
	}
	if !slices.Contains(aliases, "5") {
		t.Fatal("no 5")
	}
}
