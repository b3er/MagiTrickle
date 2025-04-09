package app

import (
	"context"
	"fmt"
	"net"
	"time"

	dnsMitmProxy "magitrickle/dns-mitm-proxy"
	"magitrickle/records"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

func (a *App) initDNSMITM() {
	a.dnsMITM = &dnsMitmProxy.DNSMITMProxy{
		UpstreamDNSAddress: a.config.DNSProxy.Upstream.Address,
		UpstreamDNSPort:    a.config.DNSProxy.Upstream.Port,
		RequestHook:        a.dnsRequestHook,
		ResponseHook:       a.dnsResponseHook,
	}
	a.records = records.New()
}

func (a *App) startDNSListeners(ctx context.Context, errChan chan error) {
	go func() {
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", a.config.DNSProxy.Host.Address, a.config.DNSProxy.Host.Port))
		if err != nil {
			errChan <- fmt.Errorf("failed to resolve udp address: %v", err)
			return
		}
		if err = a.dnsMITM.ListenUDP(ctx, addr); err != nil {
			errChan <- fmt.Errorf("failed to serve DNS UDP proxy: %v", err)
		}
	}()

	go func() {
		addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", a.config.DNSProxy.Host.Address, a.config.DNSProxy.Host.Port))
		if err != nil {
			errChan <- fmt.Errorf("failed to resolve tcp address: %v", err)
			return
		}
		if err = a.dnsMITM.ListenTCP(ctx, addr); err != nil {
			errChan <- fmt.Errorf("failed to serve DNS TCP proxy: %v", err)
		}
	}()
}

// dnsRequestHook обрабатывает входящие DNS-запросы
// usedEDNS0 is a context flag to track if we added EDNS0 to a request
type usedEDNS0Key struct{}
var usedEDNS0ContextKey = usedEDNS0Key{}

func (a *App) dnsRequestHook(clientAddr net.Addr, reqMsg dns.Msg, network string) (*dns.Msg, *dns.Msg, error) {
	var clientAddrStr string
	var clientIP net.IP
	if clientAddr != nil {
		clientAddrStr = clientAddr.String()
		// Extract IP from client address (strip port)
		host, _, err := net.SplitHostPort(clientAddrStr)
		if err == nil {
			clientIP = net.ParseIP(host)
		}
	}
	for _, q := range reqMsg.Question {
		log.Trace().
			Str("name", q.Name).
			Int("qtype", int(q.Qtype)).
			Int("qclass", int(q.Qclass)).
			Str("clientAddr", clientAddrStr).
			Str("network", network).
			Msg("requested record")
	}

	// Create a modified request to send upstream
	modifiedReq := reqMsg.Copy()

	// Check if EDNS0 is enabled in config
	enableEDNS0 := a.config.DNSProxy.EnableEDNS0

	// Add EDNS0 Client Subnet option if we have a valid client IP and EDNS0 is enabled
	if enableEDNS0 && clientIP != nil {
		// Determine subnet mask (use /24 for IPv4 and /56 for IPv6)
		mask := 24
		if clientIP.To4() == nil {
			mask = 56
		}

		// Create or update the OPT record
		var opt *dns.OPT
		for _, rr := range modifiedReq.Extra {
			if rr.Header().Rrtype == dns.TypeOPT {
				opt = rr.(*dns.OPT)
				break
			}
		}

		if opt == nil {
			// Create new OPT record if it doesn't exist
			opt = new(dns.OPT)
			opt.Hdr.Name = "."
			opt.Hdr.Rrtype = dns.TypeOPT
			opt.Hdr.Class = dns.DefaultMsgSize
			// Set EDNS version to 0 (very important)
			opt.Hdr.Ttl = 0 // This sets EDNS version to 0 with no flags
			modifiedReq.Extra = append(modifiedReq.Extra, opt)
		}

		// Add client subnet option
		e := new(dns.EDNS0_SUBNET)
		e.Code = dns.EDNS0SUBNET
		e.Family = 1 // IPv4
		if clientIP.To4() == nil {
			e.Family = 2 // IPv6
		}
		e.SourceNetmask = uint8(mask)
		e.SourceScope = 0
		e.Address = clientIP

		// Add the ECS option to the OPT record
		opt.Option = append(opt.Option, e)
		
		// Log that we're adding EDNS0 Client Subnet
		log.Debug().
			Str("clientIP", clientIP.String()).
			Uint8("mask", uint8(mask)).
			Str("family", fmt.Sprintf("%d", e.Family)).
			Msg("adding EDNS0 client subnet")
	}

	if a.config.DNSProxy.DisableFakePTR {
		return modifiedReq, nil, nil
	}

	if len(reqMsg.Question) == 1 && reqMsg.Question[0].Qtype == dns.TypePTR {
		respMsg := &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:                 reqMsg.Id,
				Response:           true,
				RecursionAvailable: true,
				Rcode:              dns.RcodeNameError,
			},
			Question: reqMsg.Question,
		}
		return nil, respMsg, nil
	}

	return modifiedReq, nil, nil
}

// dnsResponseHook обрабатывает ответы DNS
func (a *App) dnsResponseHook(clientAddr net.Addr, reqMsg dns.Msg, respMsg dns.Msg, network string) (*dns.Msg, error) {
	defer a.handleMessage(respMsg, clientAddr, &network)

	if a.config.DNSProxy.DisableDropAAAA {
		return nil, nil
	}

	// фильтрация записей AAAA
	var filteredAnswers []dns.RR
	for _, answer := range respMsg.Answer {
		if answer.Header().Rrtype != dns.TypeAAAA {
			filteredAnswers = append(filteredAnswers, answer)
		}
	}
	respMsg.Answer = filteredAnswers

	return &respMsg, nil
}

// handleMessage обрабатывает полученное DNS-сообщение
func (a *App) handleMessage(msg dns.Msg, clientAddr net.Addr, network *string) {
	for _, rr := range msg.Answer {
		a.handleRecord(rr, clientAddr, network)
	}
}

// handleRecord маршрутизирует обработку DNS-записи в зависимости от её типа (A или CNAME)
func (a *App) handleRecord(rr dns.RR, clientAddr net.Addr, network *string) {
	switch v := rr.(type) {
	case *dns.A:
		a.processARecord(*v, clientAddr, network)
	case *dns.CNAME:
		a.processCNameRecord(*v, clientAddr, network)
	}
}

func (a *App) processARecord(aRecord dns.A, clientAddr net.Addr, network *string) {
	var clientAddrStr, networkStr string
	if clientAddr != nil {
		clientAddrStr = clientAddr.String()
	}
	if network != nil {
		networkStr = *network
	}
	log.Trace().
		Str("name", aRecord.Hdr.Name).
		Str("address", aRecord.A.String()).
		Int("ttl", int(aRecord.Hdr.Ttl)).
		Str("clientAddr", clientAddrStr).
		Str("network", networkStr).
		Msg("processing a record")

	ttlDuration := aRecord.Hdr.Ttl + a.config.Netfilter.IPSet.AdditionalTTL

	a.records.AddARecord(aRecord.Hdr.Name[:len(aRecord.Hdr.Name)-1], aRecord.A, ttlDuration)

	names := a.records.GetAliases(aRecord.Hdr.Name[:len(aRecord.Hdr.Name)-1])
	for _, group := range a.groups {
	Rule:
		for _, domain := range group.Rules {
			if !domain.IsEnabled() {
				continue
			}
			for _, name := range names {
				if !domain.IsMatch(name) {
					continue
				}
				// TODO: Check already existed
				if err := group.AddIP(aRecord.A, ttlDuration); err != nil {
					log.Error().
						Str("address", aRecord.A.String()).
						Err(err).
						Msg("failed to add address")
				} else {
					log.Debug().
						Str("address", aRecord.A.String()).
						Str("aRecordDomain", aRecord.Hdr.Name).
						Str("cNameDomain", name).
						Msg("add address")
				}
				break Rule
			}
		}
	}
}

func (a *App) processCNameRecord(cNameRecord dns.CNAME, clientAddr net.Addr, network *string) {
	var clientAddrStr, networkStr string
	if clientAddr != nil {
		clientAddrStr = clientAddr.String()
	}
	if network != nil {
		networkStr = *network
	}
	log.Trace().
		Str("name", cNameRecord.Hdr.Name).
		Str("cname", cNameRecord.Target).
		Int("ttl", int(cNameRecord.Hdr.Ttl)).
		Str("clientAddr", clientAddrStr).
		Str("network", networkStr).
		Msg("processing cname record")

	ttlDuration := cNameRecord.Hdr.Ttl + a.config.Netfilter.IPSet.AdditionalTTL

	a.records.AddCNameRecord(cNameRecord.Hdr.Name[:len(cNameRecord.Hdr.Name)-1],
		cNameRecord.Target[:len(cNameRecord.Target)-1],
		ttlDuration)

	now := time.Now()
	aRecords := a.records.GetARecords(cNameRecord.Hdr.Name[:len(cNameRecord.Hdr.Name)-1])
	names := a.records.GetAliases(cNameRecord.Hdr.Name[:len(cNameRecord.Hdr.Name)-1])
	for _, group := range a.groups {
	Rule:
		for _, domain := range group.Rules {
			if !domain.IsEnabled() {
				continue
			}
			for _, name := range names {
				if !domain.IsMatch(name) {
					continue
				}
				for _, aRecord := range aRecords {
					if err := group.AddIP(aRecord.Address, uint32(now.Sub(aRecord.Deadline).Seconds())); err != nil {
						log.Error().
							Str("address", aRecord.Address.String()).
							Err(err).
							Msg("failed to add address")
					} else {
						log.Debug().
							Str("address", aRecord.Address.String()).
							Str("cNameDomain", name).
							Msg("add address")
					}
				}
				continue Rule
			}
		}
	}
}
