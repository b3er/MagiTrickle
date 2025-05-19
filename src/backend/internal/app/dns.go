package app

import (
	"context"
	"fmt"
	"net"
	"time"

	dnsMitmProxy "magitrickle/dns-mitm-proxy"
	"magitrickle/models"
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

// getDNSServers returns a list of all DNS servers to listen on, including the legacy Host and the new Hosts list
func (a *App) getDNSServers() []models.DNSProxyServer {
	var servers []models.DNSProxyServer

	// Add hosts from the Hosts list if it exists
	if len(a.config.DNSProxy.Hosts) > 0 {
		servers = append(servers, a.config.DNSProxy.Hosts...)
	} else {
		// Add the main host only if hosts are not defined (legacy configuration)
		servers = append(servers, a.config.DNSProxy.Host)
	}
	return servers
}

func (a *App) startDNSListeners(ctx context.Context, errChan chan error) {
	// Start listeners for all DNS hosts
	servers := a.getDNSServers()

	// Start UDP listeners
	for _, server := range servers {
		go func(server models.DNSProxyServer) {
			addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", server.Address, server.Port))
			if err != nil {
				errChan <- fmt.Errorf("failed to resolve udp address %s:%d: %v", server.Address, server.Port, err)
				return
			}
			log.Info().Str("address", addr.String()).Msg("starting DNS UDP listener")
			if err = a.dnsMITM.ListenUDP(ctx, addr); err != nil {
				errChan <- fmt.Errorf("failed to serve DNS UDP proxy on %s:%d: %v", server.Address, server.Port, err)
			}
		}(server)
	}

	// Start TCP listeners
	for _, server := range servers {
		go func(server models.DNSProxyServer) {
			addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", server.Address, server.Port))
			if err != nil {
				errChan <- fmt.Errorf("failed to resolve tcp address %s:%d: %v", server.Address, server.Port, err)
				return
			}
			log.Info().Str("address", addr.String()).Msg("starting DNS TCP listener")
			if err = a.dnsMITM.ListenTCP(ctx, addr); err != nil {
				errChan <- fmt.Errorf("failed to serve DNS TCP proxy on %s:%d: %v", server.Address, server.Port, err)
			}
		}(server)
	}
}

// dnsRequestHook processes incoming DNS requests
func (a *App) dnsRequestHook(clientAddr net.Addr, reqMsg dns.Msg, network string) (*dns.Msg, *dns.Msg, error) {
	var clientAddrStr string
	if clientAddr != nil {
		clientAddrStr = clientAddr.String()
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

	// If fake PTR responses are disabled, but the request is specifically a PTR query
	if a.config.DNSProxy.DisableFakePTR && len(reqMsg.Question) == 1 && reqMsg.Question[0].Qtype == dns.TypePTR {
		// Check if the request is in the cache
		ptrName := reqMsg.Question[0].Name
		cachedRecord := a.records.GetPTRRecord(ptrName)
		if cachedRecord != nil {
			// Return the cached response
			ptrRR, err := dns.NewRR(fmt.Sprintf("%s PTR %s", ptrName, cachedRecord.Hostname))
			if err == nil {
				respMsg := &dns.Msg{
					MsgHdr: dns.MsgHdr{
						Id:                 reqMsg.Id,
						Response:           true,
						RecursionAvailable: true,
						Rcode:              dns.RcodeSuccess,
					},
					Question: reqMsg.Question,
					Answer:   []dns.RR{ptrRR},
				}
				log.Debug().
					Str("ptr", ptrName).
					Str("cached_hostname", cachedRecord.Hostname).
					Msg("using cached PTR record")
				return nil, respMsg, nil
			}
		}
		// If the record is not in cache, let the request go to the upstream server
		// but we've modified dnsResponseHook to cache the responses
		return nil, nil, nil
	}

	// If PTR faking is enabled and the request is a PTR query - simply return NXDOMAIN
	if !a.config.DNSProxy.DisableFakePTR && len(reqMsg.Question) == 1 && reqMsg.Question[0].Qtype == dns.TypePTR {
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

	return nil, nil, nil
}

// dnsResponseHook processes DNS responses
func (a *App) dnsResponseHook(clientAddr net.Addr, reqMsg dns.Msg, respMsg dns.Msg, network string) (*dns.Msg, error) {
	defer a.handleMessage(respMsg, clientAddr, &network)

	// If this is a response to a PTR query and PTR caching is enabled (DisableFakePTR=true),
	// save the result in the cache
	if a.config.DNSProxy.DisableFakePTR && len(reqMsg.Question) == 1 && reqMsg.Question[0].Qtype == dns.TypePTR {
		ptrName := reqMsg.Question[0].Name

		// Process only successful responses
		if respMsg.Rcode == dns.RcodeSuccess {
			for _, answer := range respMsg.Answer {
				if ptr, ok := answer.(*dns.PTR); ok {
					// Cache the PTR record
					a.records.AddPTRRecord(ptrName, ptr.Ptr, ptr.Hdr.Ttl)
					log.Debug().
						Str("ptr", ptrName).
						Str("hostname", ptr.Ptr).
						Uint32("ttl", ptr.Hdr.Ttl).
						Msg("caching PTR record")
				}
			}
		} else if respMsg.Rcode == dns.RcodeNameError {
			// Also cache negative responses (NXDOMAIN) with a short TTL
			a.records.AddPTRRecord(ptrName, "", 300) // TTL of 5 minutes for negative responses
			log.Debug().
				Str("ptr", ptrName).
				Msg("caching negative PTR response")
		}
	}

	if a.config.DNSProxy.DisableDropAAAA {
		return nil, nil
	}

	// filtering AAAA records
	var filteredAnswers []dns.RR
	for _, answer := range respMsg.Answer {
		if answer.Header().Rrtype != dns.TypeAAAA {
			filteredAnswers = append(filteredAnswers, answer)
		}
	}
	respMsg.Answer = filteredAnswers

	return &respMsg, nil
}

// handleMessage processes the received DNS message
func (a *App) handleMessage(msg dns.Msg, clientAddr net.Addr, network *string) {
	for _, rr := range msg.Answer {
		a.handleRecord(rr, clientAddr, network)
	}
}

// handleRecord routes the processing of DNS record depending on its type (A or CNAME)
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
