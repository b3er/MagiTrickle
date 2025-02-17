package magitrickle

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"magitrickle/dns-mitm-proxy"
	"magitrickle/group"
	"magitrickle/models"
	"magitrickle/netfilter-helper"
	"magitrickle/pkg/magitrickle-api"
	"magitrickle/records"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

var (
	ErrAlreadyRunning           = errors.New("already running")
	ErrGroupIDConflict          = errors.New("group id conflict")
	ErrRuleIDConflict           = errors.New("rule id conflict")
	ErrConfigUnsupportedVersion = errors.New("config unsupported version")
)

var DefaultAppConfig = models.App{
	DNSProxy: models.DNSProxy{
		Host:            models.DNSProxyServer{Address: "[::]", Port: 3553},
		Upstream:        models.DNSProxyServer{Address: "127.0.0.1", Port: 53},
		DisableRemap53:  false,
		DisableFakePTR:  false,
		DisableDropAAAA: false,
	},
	Netfilter: models.Netfilter{
		IPTables: models.IPTables{
			ChainPrefix: "MT_",
		},
		IPSet: models.IPSet{
			TablePrefix:   "mt_",
			AdditionalTTL: 3600,
		},
	},
	Link:     []string{"br0"},
	LogLevel: "info",
}

type App struct {
	config            models.App
	unprocessedGroups []models.Group

	dnsMITM   *dnsMitmProxy.DNSMITMProxy
	nfHelper4 *netfilterHelper.NetfilterHelper
	nfHelper6 *netfilterHelper.NetfilterHelper
	records   *records.Records
	groups    []*group.Group

	isRunning     bool
	dnsOverrider4 *netfilterHelper.PortRemap
	dnsOverrider6 *netfilterHelper.PortRemap
}

func (a *App) handleLink(event netlink.LinkUpdate) {
	switch event.Change {
	case 0x00000001:
		log.Trace().
			Str("interface", event.Link.Attrs().Name).
			Int("change", int(event.Change)).
			Msg("interface event")
		ifaceName := event.Link.Attrs().Name
		for _, group := range a.groups {
			if group.Interface != ifaceName {
				continue
			}

			err := group.LinkUpdateHook(event)
			if err != nil {
				log.Error().Str("group", group.ID.String()).Err(err).Msg("error while handling interface up")
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
	a.dnsMITM = &dnsMitmProxy.DNSMITMProxy{
		UpstreamDNSAddress: a.config.DNSProxy.Upstream.Address,
		UpstreamDNSPort:    a.config.DNSProxy.Upstream.Port,
		RequestHook: func(clientAddr net.Addr, reqMsg dns.Msg, network string) (*dns.Msg, *dns.Msg, error) {
			if a.config.DNSProxy.DisableFakePTR {
				return nil, nil, nil
			}

			// TODO: Проверить на интерфейс
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
		},
		ResponseHook: func(clientAddr net.Addr, reqMsg dns.Msg, respMsg dns.Msg, network string) (*dns.Msg, error) {
			defer a.handleMessage(respMsg, clientAddr, &network)

			if a.config.DNSProxy.DisableDropAAAA {
				return nil, nil
			}

			var idx int
			for _, answer := range respMsg.Answer {
				if answer.Header().Rrtype == dns.TypeAAAA {
					continue
				}
				respMsg.Answer[idx] = answer
				idx++
			}
			respMsg.Answer = respMsg.Answer[:idx]

			return &respMsg, nil
		},
	}
	a.records = records.New()

	nh4, err := netfilterHelper.New(false)
	if err != nil {
		return fmt.Errorf("netfilter helper init fail: %w", err)
	}
	err = nh4.CleanIPTables(a.config.Netfilter.IPTables.ChainPrefix)
	if err != nil {
		return fmt.Errorf("failed to clear iptables: %w", err)
	}
	a.nfHelper4 = nh4

	nh6, err := netfilterHelper.New(true)
	if err != nil {
		return fmt.Errorf("netfilter helper init fail: %w", err)
	}
	err = nh6.CleanIPTables(a.config.Netfilter.IPTables.ChainPrefix)
	if err != nil {
		return fmt.Errorf("failed to clear iptables: %w", err)
	}
	a.nfHelper6 = nh6

	newCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errChan := make(chan error)

	/*
		DNS Proxy
	*/

	go func() {
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", a.config.DNSProxy.Host.Address, a.config.DNSProxy.Host.Port))
		if err != nil {
			errChan <- fmt.Errorf("failed to resolve udp address: %v", err)
			return
		}
		err = a.dnsMITM.ListenUDP(newCtx, addr)
		if err != nil {
			errChan <- fmt.Errorf("failed to serve DNS UDP proxy: %v", err)
			return
		}
	}()

	go func() {
		addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", a.config.DNSProxy.Host.Address, a.config.DNSProxy.Host.Port))
		if err != nil {
			errChan <- fmt.Errorf("failed to resolve tcp address: %v", err)
			return
		}
		err = a.dnsMITM.ListenTCP(newCtx, addr)
		if err != nil {
			errChan <- fmt.Errorf("failed to serve DNS TCP proxy: %v", err)
			return
		}
	}()

	var addrList []netlink.Addr
	for _, linkName := range a.config.Link {
		link, err := netlink.LinkByName(linkName)
		if err != nil {
			return fmt.Errorf("failed to find link %s: %w", linkName, err)
		}
		linkAddrList, err := netlink.AddrList(link, nl.FAMILY_ALL)
		if err != nil {
			return fmt.Errorf("failed to list address of interface: %w", err)
		}
		addrList = append(addrList, linkAddrList...)
	}

	if !a.config.DNSProxy.DisableRemap53 {
		a.dnsOverrider4 = a.nfHelper4.PortRemap(fmt.Sprintf("%sDNSOR", a.config.Netfilter.IPTables.ChainPrefix), 53, a.config.DNSProxy.Host.Port, addrList)
		err = a.dnsOverrider4.Enable()
		if err != nil {
			return fmt.Errorf("failed to override DNS (IPv4): %v", err)
		}
		defer func() { _ = a.dnsOverrider4.Disable() }()

		a.dnsOverrider6 = a.nfHelper6.PortRemap(fmt.Sprintf("%sDNSOR", a.config.Netfilter.IPTables.ChainPrefix), 53, a.config.DNSProxy.Host.Port, addrList)
		err = a.dnsOverrider6.Enable()
		if err != nil {
			return fmt.Errorf("failed to override DNS (IPv6): %v", err)
		}
		defer func() { _ = a.dnsOverrider6.Disable() }()
	}

	/*
		Groups
	*/

	for _, group := range a.unprocessedGroups {
		err := a.AddGroup(group)
		if err != nil {
			return err
		}
	}
	for _, group := range a.groups {
		err = group.Enable()
		if err != nil {
			return fmt.Errorf("failed to enable group: %w", err)
		}
	}
	defer func() {
		for _, group := range a.groups {
			_ = group.Destroy()
		}
	}()

	/*
		Socket (for netfilter.d events)
	*/
	err = os.Remove(magitrickleAPI.SocketPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove existed UNIX socket: %w", err)
	}
	socket, err := net.Listen("unix", magitrickleAPI.SocketPath)
	if err != nil {
		return fmt.Errorf("error while serve UNIX socket: %v", err)
	}
	defer func() {
		_ = socket.Close()
		_ = os.Remove(magitrickleAPI.SocketPath)
	}()

	go func() {
		err := http.Serve(socket, a.apiHandler())
		if err != nil {
			errChan <- fmt.Errorf("failed to serve UNIX socket: %v", err)
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
	defer close(linkUpdateDone)

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

func (a *App) AddGroup(groupModel models.Group) error {
	for _, group := range a.groups {
		if groupModel.ID == group.ID {
			return ErrGroupIDConflict
		}
	}
	dup := make(map[[4]byte]struct{})
	for _, rule := range groupModel.Rules {
		if _, exists := dup[rule.ID]; exists {
			return ErrRuleIDConflict
		}
		dup[rule.ID] = struct{}{}
	}

	grp, err := group.NewGroup(groupModel, a.nfHelper4, a.config.Netfilter.IPTables.ChainPrefix, a.config.Netfilter.IPSet.TablePrefix)
	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}
	a.groups = append(a.groups, grp)

	log.Debug().Str("id", grp.ID.String()).Str("name", grp.Name).Msg("added group")

	if a.isRunning {
		return grp.Sync(a.records)
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
				err := group.AddIP(aRecord.A, ttlDuration)
				if err != nil {
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

	a.records.AddCNameRecord(cNameRecord.Hdr.Name[:len(cNameRecord.Hdr.Name)-1], cNameRecord.Target[:len(cNameRecord.Target)-1], ttlDuration)

	// TODO: Optimization
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
					err := group.AddIP(aRecord.Address, uint32(now.Sub(aRecord.Deadline).Seconds()))
					if err != nil {
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

func (a *App) handleRecord(rr dns.RR, clientAddr net.Addr, network *string) {
	switch v := rr.(type) {
	case *dns.A:
		a.processARecord(*v, clientAddr, network)
	case *dns.CNAME:
		a.processCNameRecord(*v, clientAddr, network)
	default:
	}
}

func (a *App) handleMessage(msg dns.Msg, clientAddr net.Addr, network *string) {
	for _, rr := range msg.Answer {
		a.handleRecord(rr, clientAddr, network)
	}
}

func (a *App) ImportConfig(cfg models.Config) error {
	if !strings.HasPrefix(cfg.ConfigVersion, "0.1.") {
		return ErrConfigUnsupportedVersion
	}

	if cfg.App.DNSProxy.Upstream.Address != "" {
		a.config.DNSProxy.Upstream.Address = cfg.App.DNSProxy.Upstream.Address
	}
	if cfg.App.DNSProxy.Upstream.Port != 0 {
		a.config.DNSProxy.Upstream.Port = cfg.App.DNSProxy.Upstream.Port
	}
	if cfg.App.DNSProxy.Host.Address != "" {
		a.config.DNSProxy.Host.Address = cfg.App.DNSProxy.Host.Address
	}
	if cfg.App.DNSProxy.Host.Port != 0 {
		a.config.DNSProxy.Host.Port = cfg.App.DNSProxy.Host.Port
	}
	a.config.DNSProxy.DisableRemap53 = cfg.App.DNSProxy.DisableRemap53
	a.config.DNSProxy.DisableFakePTR = cfg.App.DNSProxy.DisableFakePTR
	a.config.DNSProxy.DisableDropAAAA = cfg.App.DNSProxy.DisableDropAAAA
	if cfg.App.Netfilter.IPTables.ChainPrefix != "" {
		a.config.Netfilter.IPTables.ChainPrefix = cfg.App.Netfilter.IPTables.ChainPrefix
	}
	if cfg.App.Netfilter.IPSet.TablePrefix != "" {
		a.config.Netfilter.IPSet.TablePrefix = cfg.App.Netfilter.IPSet.TablePrefix
	}
	a.config.Netfilter.IPSet.AdditionalTTL = cfg.App.Netfilter.IPSet.AdditionalTTL

	a.unprocessedGroups = cfg.Groups

	return nil
}

func (a *App) ExportConfig() models.Config {
	groups := make([]models.Group, len(a.groups))
	for idx, group := range a.groups {
		groups[idx] = group.Group
	}
	return models.Config{
		ConfigVersion: "0.1.0",
		App:           a.config,
		Groups:        groups,
	}
}

func New() *App {
	return &App{config: DefaultAppConfig}
}
