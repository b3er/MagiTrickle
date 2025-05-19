package records

import (
	"bytes"
	"net"
	"sync"
	"time"
	"strings"
)

type ARecord struct {
	Address  net.IP
	Deadline time.Time
}

type CNameRecord struct {
	Alias    string
	Deadline time.Time
}

type PTRRecord struct {
	Hostname string
	Deadline time.Time
}

type Records struct {
	locker  sync.Mutex
	records map[string]interface{}
	// Cache for PTR records to optimize reverse lookups
	ptrCache map[string]*PTRRecord
}

func (r *Records) AddCNameRecord(domainName, alias string, ttl uint32) {
	if domainName == alias {
		return
	}

	r.locker.Lock()
	r.records[domainName] = &CNameRecord{
		Alias:    alias,
		Deadline: time.Now().Add(time.Duration(ttl) * time.Second),
	}
	r.locker.Unlock()
}

func (r *Records) AddARecord(domainName string, addr net.IP, ttl uint32) {
	r.locker.Lock()
	defer r.locker.Unlock()

	deadline := time.Now().Add(time.Duration(ttl) * time.Second)

	aRecords, _ := r.records[domainName].([]*ARecord)
	for _, aRecord := range aRecords {
		if bytes.Compare(aRecord.Address, addr) != 0 {
			continue
		}
		aRecord.Deadline = deadline
		return
	}

	r.records[domainName] = append(aRecords, &ARecord{
		Address:  addr,
		Deadline: deadline,
	})
}

func (r *Records) GetAliases(domainName string) []string {
	r.locker.Lock()
	defer r.locker.Unlock()
	r.cleanupRecords()

	domains := make(map[string]struct{})
	domains[domainName] = struct{}{}

	for {
		var addedNew bool
		for name, aRecord := range r.records {
			if _, ok := domains[name]; ok {
				continue
			}
			cname, ok := aRecord.(*CNameRecord)
			if !ok {
				continue
			}
			if _, ok = domains[cname.Alias]; !ok {
				continue
			}

			domains[name] = struct{}{}
			addedNew = true
		}
		if !addedNew {
			break
		}
	}

	domainList := make([]string, len(domains))
	idx := 0
	for name, _ := range domains {
		domainList[idx] = name
		idx++
	}

	return domainList
}

func (r *Records) GetARecords(domainName string) []*ARecord {
	r.locker.Lock()
	defer r.locker.Unlock()
	r.cleanupRecords()

	loopDetect := make(map[string]struct{})
	loopDetect[domainName] = struct{}{}
	for {
		switch v := r.records[domainName].(type) {
		case *CNameRecord:
			if _, ok := loopDetect[v.Alias]; ok {
				return nil
			}
			domainName = v.Alias
			loopDetect[v.Alias] = struct{}{}
		case []*ARecord:
			return v
		default:
			return nil
		}
	}
}

func (r *Records) ListKnownDomains() []string {
	r.locker.Lock()
	defer r.locker.Unlock()
	r.cleanupRecords()

	domainsList := make([]string, len(r.records))
	i := 0
	for name, _ := range r.records {
		domainsList[i] = name
		i++
	}
	return domainsList
}

func (r *Records) cleanupRecords() {
	now := time.Now()
	for name, records := range r.records {
		switch v := records.(type) {
		case []*ARecord:
			idx := 0
			for _, aRecord := range v {
				if now.After(aRecord.Deadline) {
					continue
				}
				v[idx] = aRecord
				idx++
			}
			if idx == 0 {
				delete(r.records, name)
				break
			}
			r.records[name] = v[:idx]
		case *CNameRecord:
			if !now.After(v.Deadline) {
				continue
			}
			delete(r.records, name)
		}
	}
}

func (r *Records) AddPTRRecord(ip string, hostname string, ttl uint32) {
	r.locker.Lock()
	defer r.locker.Unlock()
	
	// Normalize the IP address to use as a key
	ipNormalized := strings.TrimSuffix(ip, ".")
	
	r.ptrCache[ipNormalized] = &PTRRecord{
		Hostname: hostname,
		Deadline: time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

func (r *Records) GetPTRRecord(ip string) *PTRRecord {
	r.locker.Lock()
	defer r.locker.Unlock()
	
	// Check and clean up expired records
	r.cleanupPTRRecords()
	
	// Normalize the IP address for lookup
	ipNormalized := strings.TrimSuffix(ip, ".")
	
	if record, ok := r.ptrCache[ipNormalized]; ok {
		return record
	}
	return nil
}

func (r *Records) cleanupPTRRecords() {
	now := time.Now()
	for ip, record := range r.ptrCache {
		if now.After(record.Deadline) {
			delete(r.ptrCache, ip)
		}
	}
}

func New() *Records {
	return &Records{
		records: make(map[string]interface{}),
		ptrCache: make(map[string]*PTRRecord),
	}
}
