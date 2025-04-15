package records

import (
	"net"
	"testing"
)

func TestAAAARecord(t *testing.T) {
	r := New()
	ipv6 := net.ParseIP("2001:db8::1")
	if ipv6 == nil || ipv6.To16() == nil {
		t.Fatal("Invalid IPv6 address")
	}
	r.AddARecord("ipv6.example.com", ipv6, 60)
	records := r.GetARecords("ipv6.example.com")
	if records == nil || len(records) == 0 {
		t.Fatal("No AAAA records found")
	}
	if !records[0].Address.Equal(ipv6) {
		t.Fatalf("Expected %v, got %v", ipv6, records[0].Address)
	}
}

func TestPTRRecordIPv6(t *testing.T) {
	r := New()
	ptrName := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
	hostname := "ipv6host.example.com."
	ttl := uint32(300)

	// Add IPv6 PTR record
	r.AddPTRRecord(ptrName, hostname, ttl)

	// Verify record was stored
	record := r.GetPTRRecord(ptrName)
	if record == nil {
		t.Fatal("IPv6 PTR record not found after adding")
	}
	if record.Hostname != hostname {
		t.Fatalf("Expected hostname %s, got %s", hostname, record.Hostname)
	}
}
