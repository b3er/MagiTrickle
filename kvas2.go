package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"kvas2-go/dns-mitm-proxy"
	"kvas2-go/models"
	"kvas2-go/netfilter-helper"
	"kvas2-go/records"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

var (
	ErrAlreadyRunning  = errors.New("already running")
	ErrGroupIDConflict = errors.New("group id conflict")
)

type Config struct {
	MinimalTTL             time.Duration
	ChainPrefix            string
	IpSetPrefix            string
	LinkName               string
	TargetDNSServerAddress string
	ListenDNSPort          uint16
}

type App struct {
	Config Config

	DNSMITM          *dnsMitmProxy.DNSMITMProxy
	NetfilterHelper4 *netfilterHelper.NetfilterHelper
	NetfilterHelper6 *netfilterHelper.NetfilterHelper
	Records          *records.Records
	Groups           map[uuid.UUID]*Group

	Link netlink.Link

	isRunning     bool
	dnsOverrider4 *netfilterHelper.PortRemap
	dnsOverrider6 *netfilterHelper.PortRemap
}

func (a *App) handleLink(event netlink.LinkUpdate) {
	switch event.Change {
	case 0x00000001:
		log.Debug().
			Str("interface", event.Link.Attrs().Name).
			Str("operstatestr", event.Attrs().OperState.String()).
			Int("operstate", int(event.Attrs().OperState)).
			Msg("interface change")
		switch event.Attrs().OperState {
		case netlink.OperUp:
			ifaceName := event.Link.Attrs().Name
			for _, group := range a.Groups {
				if group.Interface != ifaceName {
					continue
				}

				err := group.ipsetToLink.LinkUpdateHook()
				if err != nil {
					log.Error().Str("group", group.ID.String()).Err(err).Msg("error while handling interface up")
				}
			}
		}
	case 0xFFFFFFFF:
		switch event.Header.Type {
		case 16:
			log.Debug().
				Str("interface", event.Link.Attrs().Name).
				Int("type", int(event.Header.Type)).
				Msg("interface add")
		case 17:
			log.Debug().
				Str("interface", event.Link.Attrs().Name).
				Int("type", int(event.Header.Type)).
				Msg("interface del")
		}
	}
}

func (a *App) start(ctx context.Context) (err error) {
	newCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errChan := make(chan error)

	/*
		DNS Proxy
	*/

	go func() {
		addr, err := net.ResolveUDPAddr("udp", "[::]:"+strconv.Itoa(int(a.Config.ListenDNSPort)))
		if err != nil {
			errChan <- fmt.Errorf("failed to resolve udp address: %v", err)
			return
		}
		err = a.DNSMITM.ListenUDP(newCtx, addr)
		if err != nil {
			errChan <- fmt.Errorf("failed to serve DNS UDP proxy: %v", err)
			return
		}
	}()

	go func() {
		addr, err := net.ResolveTCPAddr("tcp", "[::]:"+strconv.Itoa(int(a.Config.ListenDNSPort)))
		if err != nil {
			errChan <- fmt.Errorf("failed to resolve tcp address: %v", err)
			return
		}
		err = a.DNSMITM.ListenTCP(newCtx, addr)
		if err != nil {
			errChan <- fmt.Errorf("failed to serve DNS TCP proxy: %v", err)
			return
		}
	}()

	addrList, err := netlink.AddrList(a.Link, nl.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to list address of interface: %w", err)
	}

	a.dnsOverrider4 = a.NetfilterHelper4.PortRemap(fmt.Sprintf("%sDNSOR", a.Config.ChainPrefix), 53, a.Config.ListenDNSPort, addrList)
	err = a.dnsOverrider4.Enable()
	if err != nil {
		return fmt.Errorf("failed to override DNS (IPv4): %v", err)
	}
	defer func() { _ = a.dnsOverrider4.Disable() }()

	a.dnsOverrider6 = a.NetfilterHelper6.PortRemap(fmt.Sprintf("%sDNSOR", a.Config.ChainPrefix), 53, a.Config.ListenDNSPort, addrList)
	err = a.dnsOverrider6.Enable()
	if err != nil {
		return fmt.Errorf("failed to override DNS (IPv6): %v", err)
	}
	defer func() { _ = a.dnsOverrider6.Disable() }()

	/*
		Groups
	*/

	for _, group := range a.Groups {
		err = group.Enable()
		if err != nil {
			return fmt.Errorf("failed to enable group: %w", err)
		}
	}
	defer func() {
		for _, group := range a.Groups {
			_ = group.Disable()
		}
	}()

	/*
		Socket (for netfilter.d events)
	*/
	socketPath := "/opt/var/run/kvas2-go.sock"
	err = os.Remove(socketPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove existed UNIX socket: %w", err)
	}
	socket, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("error while serve UNIX socket: %v", err)
	}
	defer func() {
		_ = socket.Close()
		_ = os.Remove(socketPath)
	}()

	go func() {
		for {
			if newCtx.Err() != nil {
				return
			}

			conn, err := socket.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					log.Error().Err(err).Msg("error while listening unix socket")
				}
				break
			}

			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()

				buf := make([]byte, 1024)
				n, err := conn.Read(buf)
				if err != nil {
					return
				}

				args := strings.Split(string(buf[:n]), ":")
				if len(args) == 3 && args[0] == "netfilter.d" {
					log.Debug().Str("table", args[2]).Msg("netfilter.d event")
					if a.dnsOverrider4.Enabled {
						err := a.dnsOverrider4.PutIPTable(args[2])
						if err != nil {
							log.Error().Err(err).Msg("error while fixing iptables after netfilter.d")
						}
					}
					if a.dnsOverrider6.Enabled {
						err = a.dnsOverrider6.PutIPTable(args[2])
						if err != nil {
							log.Error().Err(err).Msg("error while fixing iptables after netfilter.d")
						}
					}
					for _, group := range a.Groups {
						err := group.ipsetToLink.NetfilerDHook(args[2])
						if err != nil {
							log.Error().Err(err).Msg("error while fixing iptables after netfilter.d")
						}
					}
				}
			}(conn)
		}
	}()

	/*
		Interface updates
	*/
	linkUpdateChannel := make(chan netlink.LinkUpdate)
	linkUpdateDone := make(chan struct{})
	err = netlink.LinkSubscribe(linkUpdateChannel, linkUpdateDone)
	if err != nil {
		return fmt.Errorf("failed to subscribe to link updates: %w", err)
	}
	defer func() {
		close(linkUpdateDone)
	}()

	/*
		Global loop
	*/
	for {
		select {
		case event := <-linkUpdateChannel:
			a.handleLink(event)
		case err := <-errChan:
			return err
		case <-ctx.Done():
			return nil
		}
	}
}

func (a *App) Start(ctx context.Context) (err error) {
	if a.isRunning {
		return ErrAlreadyRunning
	}
	a.isRunning = true
	defer func() {
		a.isRunning = false
	}()

	defer func() {
		if r := recover(); r != nil {
			var ok bool
			if err, ok = r.(error); !ok {
				err = fmt.Errorf("%v", r)
			}

			err = fmt.Errorf("recovered error: %w", err)
		}
	}()

	err = a.start(ctx)

	return err
}

func (a *App) AddGroup(group *models.Group) error {
	if _, exists := a.Groups[group.ID]; exists {
		return ErrGroupIDConflict
	}

	ipsetName := fmt.Sprintf("%s%8x", a.Config.IpSetPrefix, group.ID.ID())
	ipset, err := a.NetfilterHelper4.IPSet(ipsetName)
	if err != nil {
		return fmt.Errorf("failed to initialize ipset: %w", err)
	}

	grp := &Group{
		Group:       group,
		iptables:    a.NetfilterHelper4.IPTables,
		ipset:       ipset,
		ipsetToLink: a.NetfilterHelper4.IfaceToIPSet(fmt.Sprintf("%sR_%8x", a.Config.ChainPrefix, group.ID.ID()), group.Interface, ipsetName, false),
	}
	a.Groups[grp.ID] = grp
	return a.SyncGroup(grp)
}

func (a *App) SyncGroup(group *Group) error {
	now := time.Now()

	addresses := make(map[string]time.Duration)
	knownDomains := a.Records.ListKnownDomains()
	for _, domain := range group.Rules {
		if !domain.IsEnabled() {
			continue
		}

		for _, domainName := range knownDomains {
			if !domain.IsMatch(domainName) {
				continue
			}

			domainAddresses := a.Records.GetARecords(domainName)
			for _, address := range domainAddresses {
				ttl := now.Sub(address.Deadline)
				if oldTTL, ok := addresses[string(address.Address)]; !ok || ttl > oldTTL {
					addresses[string(address.Address)] = ttl
				}
			}
		}
	}

	currentAddresses, err := group.ListIPv4()
	if err != nil {
		return fmt.Errorf("failed to get old ipset list: %w", err)
	}

	for addr, ttl := range addresses {
		// TODO: Check TTL
		if _, exists := currentAddresses[addr]; exists {
			continue
		}
		ip := net.IP(addr)
		err = group.AddIPv4(ip, ttl)
		if err != nil {
			log.Error().
				Str("address", ip.String()).
				Err(err).
				Msg("failed to add address")
		} else {
			log.Trace().
				Str("address", ip.String()).
				Err(err).
				Msg("add address")
		}
	}

	for addr := range currentAddresses {
		if _, ok := addresses[addr]; ok {
			continue
		}
		ip := net.IP(addr)
		err = group.DelIPv4(ip)
		if err != nil {
			log.Error().
				Str("address", ip.String()).
				Err(err).
				Msg("failed to delete address")
		} else {
			log.Trace().
				Str("address", ip.String()).
				Err(err).
				Msg("del address")
		}
	}

	return nil
}

func (a *App) ListInterfaces() ([]net.Interface, error) {
	interfaceNames := make([]net.Interface, 0)

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagPointToPoint == 0 {
			continue
		}

		interfaceNames = append(interfaceNames, iface)
	}

	return interfaceNames, nil
}

func (a *App) processARecord(aRecord dns.A) {
	log.Trace().
		Str("name", aRecord.Hdr.Name).
		Str("address", aRecord.A.String()).
		Int("ttl", int(aRecord.Hdr.Ttl)).
		Msg("processing a record")

	ttlDuration := time.Duration(aRecord.Hdr.Ttl) * time.Second
	if ttlDuration < a.Config.MinimalTTL {
		ttlDuration = a.Config.MinimalTTL
	}

	a.Records.AddARecord(aRecord.Hdr.Name[:len(aRecord.Hdr.Name)-1], aRecord.A, ttlDuration)

	names := a.Records.GetAliases(aRecord.Hdr.Name[:len(aRecord.Hdr.Name)-1])
	for _, group := range a.Groups {
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
				err := group.AddIPv4(aRecord.A, ttlDuration)
				if err != nil {
					log.Error().
						Str("address", aRecord.A.String()).
						Err(err).
						Msg("failed to add address")
				} else {
					log.Trace().
						Str("address", aRecord.A.String()).
						Str("aRecordDomain", aRecord.Hdr.Name).
						Str("cNameDomain", name).
						Err(err).
						Msg("add address")
				}
				break Rule
			}
		}
	}
}

func (a *App) processCNameRecord(cNameRecord dns.CNAME) {
	log.Trace().
		Str("name", cNameRecord.Hdr.Name).
		Str("cname", cNameRecord.Target).
		Int("ttl", int(cNameRecord.Hdr.Ttl)).
		Msg("processing cname record")

	ttlDuration := time.Duration(cNameRecord.Hdr.Ttl) * time.Second
	if ttlDuration < a.Config.MinimalTTL {
		ttlDuration = a.Config.MinimalTTL
	}

	a.Records.AddCNameRecord(cNameRecord.Hdr.Name[:len(cNameRecord.Hdr.Name)-1], cNameRecord.Target, ttlDuration)

	// TODO: Optimization
	now := time.Now()
	aRecords := a.Records.GetARecords(cNameRecord.Hdr.Name[:len(cNameRecord.Hdr.Name)-1])
	names := a.Records.GetAliases(cNameRecord.Hdr.Name[:len(cNameRecord.Hdr.Name)-1])
	for _, group := range a.Groups {
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
					err := group.AddIPv4(aRecord.Address, now.Sub(aRecord.Deadline))
					if err != nil {
						log.Error().
							Str("address", aRecord.Address.String()).
							Err(err).
							Msg("failed to add address")
					} else {
						log.Trace().
							Str("address", aRecord.Address.String()).
							Str("cNameDomain", name).
							Err(err).
							Msg("add address")
					}
				}
				continue Rule
			}
		}
	}
}

func (a *App) handleRecord(rr dns.RR) {
	switch v := rr.(type) {
	case *dns.A:
		a.processARecord(*v)
	case *dns.CNAME:
		a.processCNameRecord(*v)
	default:
	}
}

func (a *App) handleMessage(msg dns.Msg) {
	for _, rr := range msg.Answer {
		a.handleRecord(rr)
	}
}

func New(config Config) (*App, error) {
	var err error

	app := &App{}

	app.Config = config

	app.DNSMITM = dnsMitmProxy.New()
	app.DNSMITM.TargetDNSServerAddress = app.Config.TargetDNSServerAddress
	app.DNSMITM.TargetDNSServerPort = 53
	app.DNSMITM.RequestHook = func(clientAddr net.Addr, reqMsg dns.Msg, network string) (*dns.Msg, *dns.Msg, error) {
		// TODO: Need to understand why it not works in proxy mode
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

		return nil, nil, nil
	}
	app.DNSMITM.ResponseHook = func(clientAddr net.Addr, reqMsg dns.Msg, respMsg dns.Msg, network string) (*dns.Msg, error) {
		// TODO: Make it optional
		var idx int
		for _, a := range respMsg.Answer {
			if a.Header().Rrtype == dns.TypeAAAA {
				continue
			}
			respMsg.Answer[idx] = a
			idx++
		}
		respMsg.Answer = respMsg.Answer[:idx]

		app.handleMessage(respMsg)

		return &respMsg, nil
	}

	app.Records = records.New()
	app.Groups = make(map[uuid.UUID]*Group, 0)

	link, err := netlink.LinkByName(app.Config.LinkName)
	if err != nil {
		return nil, fmt.Errorf("failed to find link %s: %w", app.Config.LinkName, err)
	}
	app.Link = link

	nh4, err := netfilterHelper.New(false)
	if err != nil {
		return nil, fmt.Errorf("netfilter helper init fail: %w", err)
	}
	app.NetfilterHelper4 = nh4
	err = app.NetfilterHelper4.ClearIPTables(app.Config.ChainPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to clear iptables: %w", err)
	}

	nh6, err := netfilterHelper.New(true)
	if err != nil {
		return nil, fmt.Errorf("netfilter helper init fail: %w", err)
	}
	app.NetfilterHelper6 = nh6
	err = app.NetfilterHelper6.ClearIPTables(app.Config.ChainPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to clear iptables: %w", err)
	}

	app.Groups = make(map[uuid.UUID]*Group)

	return app, nil
}
