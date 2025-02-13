package kvas2

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"kvas2/dns-mitm-proxy"
	"kvas2/group"
	"kvas2/models"
	"kvas2/netfilter-helper"
	"kvas2/records"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

var (
	ErrAlreadyRunning  = errors.New("already running")
	ErrGroupIDConflict = errors.New("group id conflict")
	ErrRuleIDConflict  = errors.New("rule id conflict")
)

func randomId() [4]byte {
	id := make([]byte, 4)
	binary.BigEndian.PutUint32(id, rand.Uint32())
	return [4]byte(id)
}

type Config struct {
	AdditionalTTL          uint32
	ChainPrefix            string
	IPSetPrefix            string
	LinkName               string
	TargetDNSServerAddress string
	TargetDNSServerPort    uint16
	ListenDNSPort          uint16
}

type App struct {
	Config Config

	DNSMITM          *dnsMitmProxy.DNSMITMProxy
	NetfilterHelper4 *netfilterHelper.NetfilterHelper
	NetfilterHelper6 *netfilterHelper.NetfilterHelper
	Records          *records.Records
	Groups           []*group.Group

	Link netlink.Link

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
		for _, group := range a.Groups {
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
	socketPath := "/opt/var/run/kvas2.sock"
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
					err = a.dnsOverrider4.NetfilterDHook(args[2])
					if err != nil {
						log.Error().Err(err).Msg("error while fixing iptables after netfilter.d")
					}
					err = a.dnsOverrider6.NetfilterDHook(args[2])
					if err != nil {
						log.Error().Err(err).Msg("error while fixing iptables after netfilter.d")
					}
					for _, group := range a.Groups {
						err := group.NetfilterDHook(args[2])
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

func (a *App) AddGroup(groupModel *models.Group) error {
	for _, group := range a.Groups {
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

	grp, err := group.NewGroup(groupModel, a.NetfilterHelper4, a.Config.ChainPrefix, a.Config.IPSetPrefix)
	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}
	a.Groups = append(a.Groups, grp)

	log.Debug().Str("id", grp.ID.String()).Str("name", grp.Name).Msg("added group")

	return grp.Sync(a.Records)
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

	ttlDuration := aRecord.Hdr.Ttl + a.Config.AdditionalTTL

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

	ttlDuration := cNameRecord.Hdr.Ttl + a.Config.AdditionalTTL

	a.Records.AddCNameRecord(cNameRecord.Hdr.Name[:len(cNameRecord.Hdr.Name)-1], cNameRecord.Target[:len(cNameRecord.Target)-1], ttlDuration)

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

func (a *App) ImportConfig(cfg models.ConfigFile) error {
	a.Config = Config{
		AdditionalTTL:          cfg.AppConfig.AdditionalTTL,
		ChainPrefix:            cfg.AppConfig.ChainPrefix,
		IPSetPrefix:            cfg.AppConfig.IPSetPrefix,
		LinkName:               cfg.AppConfig.LinkName,
		TargetDNSServerAddress: cfg.AppConfig.TargetDNSServerAddress,
		TargetDNSServerPort:    cfg.AppConfig.TargetDNSServerPort,
		ListenDNSPort:          cfg.AppConfig.ListenDNSPort,
	}
	return nil
}

func (a *App) ExportConfig() models.ConfigFile {
	groups := make([]models.Group, len(a.Groups))
	for idx, group := range a.Groups {
		groups[idx] = *group.Group
	}
	return models.ConfigFile{
		AppConfig: models.AppConfig{
			AdditionalTTL:          a.Config.AdditionalTTL,
			ChainPrefix:            a.Config.ChainPrefix,
			IPSetPrefix:            a.Config.IPSetPrefix,
			LinkName:               a.Config.LinkName,
			TargetDNSServerAddress: a.Config.TargetDNSServerAddress,
			TargetDNSServerPort:    a.Config.TargetDNSServerPort,
			ListenDNSPort:          a.Config.ListenDNSPort,
		},
		Groups: groups,
	}
}

func New(config models.ConfigFile) (*App, error) {
	var err error

	app := &App{}

	app.Config = Config{
		AdditionalTTL:          config.AppConfig.AdditionalTTL,
		ChainPrefix:            config.AppConfig.ChainPrefix,
		IPSetPrefix:            config.AppConfig.IPSetPrefix,
		LinkName:               config.AppConfig.LinkName,
		TargetDNSServerAddress: config.AppConfig.TargetDNSServerAddress,
		TargetDNSServerPort:    config.AppConfig.TargetDNSServerPort,
		ListenDNSPort:          config.AppConfig.ListenDNSPort,
	}

	app.DNSMITM = dnsMitmProxy.New()
	app.DNSMITM.TargetDNSServerAddress = app.Config.TargetDNSServerAddress
	app.DNSMITM.TargetDNSServerPort = app.Config.TargetDNSServerPort
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

		app.handleMessage(respMsg, clientAddr, &network)

		return &respMsg, nil
	}

	app.Records = records.New()

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
	err = app.NetfilterHelper4.CleanIPTables(app.Config.ChainPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to clear iptables: %w", err)
	}

	nh6, err := netfilterHelper.New(true)
	if err != nil {
		return nil, fmt.Errorf("netfilter helper init fail: %w", err)
	}
	app.NetfilterHelper6 = nh6
	err = app.NetfilterHelper6.CleanIPTables(app.Config.ChainPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to clear iptables: %w", err)
	}

	for _, group := range config.Groups {
		err = app.AddGroup(&group)
		if err != nil {
			return nil, err
		}
	}

	return app, nil
}
