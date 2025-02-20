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
	"magitrickle/models"
	"magitrickle/models/config"
	"magitrickle/netfilter-helper"
	"magitrickle/pkg/magitrickle-api"
	"magitrickle/records"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

//	@title		MagiTrickle API
//	@version	0.1

var (
	ErrAlreadyRunning           = errors.New("already running")
	ErrGroupIDConflict          = errors.New("group id conflict")
	ErrRuleIDConflict           = errors.New("rule id conflict")
	ErrConfigUnsupportedVersion = errors.New("config unsupported version")
)

var defaultAppConfig = models.App{
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
	config       models.App
	dnsMITM      *dnsMitmProxy.DNSMITMProxy
	nfHelper     *netfilterHelper.NetfilterHelper
	records      *records.Records
	groups       []*Group
	isRunning    bool
	dnsOverrider *netfilterHelper.PortRemap
}

// публичный метод для запуска приложения
func (a *App) Start(ctx context.Context) (err error) {
    if a.isRunning {
        return ErrAlreadyRunning
    }
    a.isRunning = true
    defer func() { a.isRunning = false }()

    // восстанавливаемся из паники и пробрасываем ошибку наружу
    defer func() {
        if r := recover(); r != nil {
            var recErr error
            if errVal, ok := r.(error); ok {
                recErr = fmt.Errorf("recovered error: %w", errVal)
            } else {
                recErr = fmt.Errorf("recovered error: %v", r)
            }
            log.Error().Err(recErr).Msg("panic recovered")

            // переписываем err, чтобы вернуть его наружу
            err = recErr
        }
    }()

    err = a.start(ctx)
    return err
}

// основной метод инициализации и запуска всех сервисов
func (a *App) start(ctx context.Context) error {
	a.setupLogging()
	a.initDNSMITM()

	nfHelper, err := netfilterHelper.New(a.config.Netfilter.IPTables.ChainPrefix)
	if err != nil {
		return fmt.Errorf("netfilter helper init fail: %w", err)
	}
	a.nfHelper = nfHelper

	if err = a.nfHelper.CleanIPTables(); err != nil {
		return fmt.Errorf("failed to clear iptables: %w", err)
	}

	newCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errChan := make(chan error)

	a.startDNSListeners(newCtx, errChan)

	interfaceAddrs, err := a.getInterfaceAddresses()
	if err != nil {
		return err
	}

	// если remap53 не отключён – переопределяем DNS-порт
	if !a.config.DNSProxy.DisableRemap53 {
		a.dnsOverrider = a.nfHelper.PortRemap("DNSOR", 53, a.config.DNSProxy.Host.Port, interfaceAddrs)
		err = a.dnsOverrider.Enable()
		if err != nil {
			return fmt.Errorf("failed to override DNS: %v", err)
		}
		defer func() { _ = a.dnsOverrider.Disable() }()
	}

	for _, group := range a.groups {
		err = group.Enable()
		if err != nil {
			return fmt.Errorf("failed to enable group: %w", err)
		}
	}
	defer func() {
		for _, group := range a.groups {
			_ = group.Disable()
		}
	}()

	socket, err := a.setupUnixSocketAPI(errChan)
	if err != nil {
		return err
	}
	defer func() {
		_ = socket.Close()
		_ = os.Remove(magitrickleAPI.SocketPath)
	}()

	linkUpdateChannel, linkUpdateDone, err := subscribeLinkUpdates()
	if err != nil {
		return err
	}
	defer close(linkUpdateDone)

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

func (a *App) setupLogging() {
	switch a.config.LogLevel {
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "fatal":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	case "panic":
		zerolog.SetGlobalLevel(zerolog.PanicLevel)
	case "nolevel":
		zerolog.SetGlobalLevel(zerolog.NoLevel)
	case "disabled":
		zerolog.SetGlobalLevel(zerolog.Disabled)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

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

func (a *App) getInterfaceAddresses() ([]netlink.Addr, error) {
	var addrList []netlink.Addr
	for _, linkName := range a.config.Link {
		link, err := netlink.LinkByName(linkName)
		if err != nil {
			return nil, fmt.Errorf("failed to find link %s: %w", linkName, err)
		}
		linkAddrList, err := netlink.AddrList(link, nl.FAMILY_ALL)
		if err != nil {
			return nil, fmt.Errorf("failed to list address of interface %s: %w", linkName, err)
		}
		addrList = append(addrList, linkAddrList...)
	}
	return addrList, nil
}

func (a *App) setupUnixSocketAPI(errChan chan error) (net.Listener, error) {
	if err := os.Remove(magitrickleAPI.SocketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to remove existing UNIX socket: %w", err)
	}
	socket, err := net.Listen("unix", magitrickleAPI.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("error while serving UNIX socket: %v", err)
	}
	go func() {
		if err := http.Serve(socket, a.apiHandler()); err != nil {
			errChan <- fmt.Errorf("failed to serve UNIX socket: %v", err)
		}
	}()
	return socket, nil
}

func subscribeLinkUpdates() (chan netlink.LinkUpdate, chan struct{}, error) {
	linkUpdateChannel := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	if err := netlink.LinkSubscribe(linkUpdateChannel, done); err != nil {
		return nil, nil, fmt.Errorf("failed to subscribe to link updates: %w", err)
	}
	return linkUpdateChannel, done, nil
}

// обработка входящих DNS запросов
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

	if a.config.DNSProxy.DisableFakePTR {
		return nil, nil, nil
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

	return nil, nil, nil
}

// обработка ответов DNS и фильтрация записей типа AAAA
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

// обработка событий изменения состояния интерфейсов
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
			if err := group.LinkUpdateHook(event); err != nil {
				log.Error().
					Str("group", group.ID.String()).
					Err(err).
					Msg("error while handling interface up")
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

// обработка полученного DNS-сообщения
func (a *App) handleMessage(msg dns.Msg, clientAddr net.Addr, network *string) {
	for _, rr := range msg.Answer {
		a.handleRecord(rr, clientAddr, network)
	}
}

// маршрутизация обработки записи в зависимости от её типа
func (a *App) handleRecord(rr dns.RR, clientAddr net.Addr, network *string) {
	switch v := rr.(type) {
	case *dns.A:
		a.processARecord(*v, clientAddr, network)
	case *dns.CNAME:
		a.processCNameRecord(*v, clientAddr, network)
	}
}

// обработка A-записи
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

// обработка CNAME-записи
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

// импорт конфигурации из внешнего источника
func (a *App) ImportConfig(cfg config.Config) error {
	if !strings.HasPrefix(cfg.ConfigVersion, "0.1.") {
		return ErrConfigUnsupportedVersion
	}

	if cfg.App != nil {
		if cfg.App.DNSProxy != nil {
			if cfg.App.DNSProxy.Upstream != nil {
				if cfg.App.DNSProxy.Upstream.Address != nil {
					a.config.DNSProxy.Upstream.Address = *cfg.App.DNSProxy.Upstream.Address
				}
				if cfg.App.DNSProxy.Upstream.Port != nil {
					a.config.DNSProxy.Upstream.Port = *cfg.App.DNSProxy.Upstream.Port
				}
			}
			if cfg.App.DNSProxy.Host != nil {
				if cfg.App.DNSProxy.Host.Address != nil {
					a.config.DNSProxy.Host.Address = *cfg.App.DNSProxy.Host.Address
				}
				if cfg.App.DNSProxy.Host.Port != nil {
					a.config.DNSProxy.Host.Port = *cfg.App.DNSProxy.Host.Port
				}
			}
			if cfg.App.DNSProxy.DisableRemap53 != nil {
				a.config.DNSProxy.DisableRemap53 = *cfg.App.DNSProxy.DisableRemap53
			}
			if cfg.App.DNSProxy.DisableFakePTR != nil {
				a.config.DNSProxy.DisableFakePTR = *cfg.App.DNSProxy.DisableFakePTR
			}
			if cfg.App.DNSProxy.DisableDropAAAA != nil {
				a.config.DNSProxy.DisableDropAAAA = *cfg.App.DNSProxy.DisableDropAAAA
			}
		}

		if cfg.App.Netfilter != nil {
			if cfg.App.Netfilter.IPTables != nil {
				if cfg.App.Netfilter.IPTables.ChainPrefix != nil {
					a.config.Netfilter.IPTables.ChainPrefix = *cfg.App.Netfilter.IPTables.ChainPrefix
				}
			}
			if cfg.App.Netfilter.IPSet != nil {
				if cfg.App.Netfilter.IPSet.TablePrefix != nil {
					a.config.Netfilter.IPSet.TablePrefix = *cfg.App.Netfilter.IPSet.TablePrefix
				}
				if cfg.App.Netfilter.IPSet.AdditionalTTL != nil {
					a.config.Netfilter.IPSet.AdditionalTTL = *cfg.App.Netfilter.IPSet.AdditionalTTL
				}
			}
		}

		if cfg.App.Link != nil {
			a.config.Link = *cfg.App.Link
		}

		if cfg.App.LogLevel != nil {
			a.config.LogLevel = *cfg.App.LogLevel
		}
	}

	if cfg.Groups != nil {
		// отключаем старые группы и очищаем срез
		for _, group := range a.groups {
			_ = group.Disable()
		}
		a.groups = a.groups[:0]

		// импортируем новые группы
		for _, group := range *cfg.Groups {
			rules := make([]*models.Rule, len(group.Rules))
			for idx, rule := range group.Rules {
				rules[idx] = &models.Rule{
					ID:     rule.ID,
					Name:   rule.Name,
					Type:   rule.Type,
					Rule:   rule.Rule,
					Enable: rule.Enable,
				}
			}
			err := a.AddGroup(&models.Group{
				ID:         group.ID,
				Name:       group.Name,
				Interface:  group.Interface,
				FixProtect: group.FixProtect,
				Rules:      rules,
			})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// экспорт текущей конфигурации приложения
func (a *App) ExportConfig() config.Config {
	groups := make([]config.Group, len(a.groups))
	for idx, group := range a.groups {
		groupCfg := config.Group{
			ID:         group.ID,
			Name:       group.Name,
			Interface:  group.Interface,
			FixProtect: group.FixProtect,
			Rules:      make([]config.Rule, len(group.Rules)),
		}
		for idx, rule := range group.Rules {
			groupCfg.Rules[idx] = config.Rule{
				ID:     rule.ID,
				Name:   rule.Name,
				Type:   rule.Type,
				Rule:   rule.Rule,
				Enable: rule.Enable,
			}
		}
		groups[idx] = groupCfg
	}

	return config.Config{
		ConfigVersion: "0.1.0",
		App: &config.App{
			DNSProxy: &config.DNSProxy{
				Host: &config.DNSProxyServer{
					Address: &a.config.DNSProxy.Host.Address,
					Port:    &a.config.DNSProxy.Host.Port,
				},
				Upstream: &config.DNSProxyServer{
					Address: &a.config.DNSProxy.Upstream.Address,
					Port:    &a.config.DNSProxy.Upstream.Port,
				},
				DisableRemap53:  &a.config.DNSProxy.DisableRemap53,
				DisableFakePTR:  &a.config.DNSProxy.DisableFakePTR,
				DisableDropAAAA: &a.config.DNSProxy.DisableDropAAAA,
			},
			Netfilter: &config.Netfilter{
				IPTables: &config.IPTables{
					ChainPrefix: &a.config.Netfilter.IPTables.ChainPrefix,
				},
				IPSet: &config.IPSet{
					TablePrefix:   &a.config.Netfilter.IPSet.TablePrefix,
					AdditionalTTL: &a.config.Netfilter.IPSet.AdditionalTTL,
				},
			},
			Link:     &a.config.Link,
			LogLevel: &a.config.LogLevel,
		},
		Groups: &groups,
	}
}

// добавление группы с проверкой на конфликты
func (a *App) AddGroup(groupModel *models.Group) error {
	// Проверка на дублирование групп.
	for _, group := range a.groups {
		if groupModel.ID == group.ID {
			return ErrGroupIDConflict
		}
	}
	// Проверка уникальности rule.ID внутри группы.
	dup := make(map[[4]byte]struct{})
	for _, rule := range groupModel.Rules {
		if _, exists := dup[rule.ID]; exists {
			return ErrRuleIDConflict
		}
		dup[rule.ID] = struct{}{}
	}

	grp, err := NewGroup(groupModel, a)
	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}
	a.groups = append(a.groups, grp)

	log.Debug().Str("id", grp.ID.String()).Str("name", grp.Name).Msg("added group")

	// Если приложение уже запущено – сразу включаем группу и синхронизируем.
	if a.isRunning {
		if err = grp.Enable(); err != nil {
			return fmt.Errorf("failed to enable group: %w", err)
		}
		if err = grp.Sync(); err != nil {
			return fmt.Errorf("failed to sync group: %w", err)
		}
	}
	return nil
}

// получение списка подходящих сетевых интерфейсов
func (a *App) ListInterfaces() ([]net.Interface, error) {
	var filteredInterfaces []net.Interface

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}

	for _, iface := range interfaces {
		// Пример фильтрации: оставляем только интерфейсы с установленным флагом PointToPoint.
		if iface.Flags&net.FlagPointToPoint == 0 {
			continue
		}
		filteredInterfaces = append(filteredInterfaces, iface)
	}

	return filteredInterfaces, nil
}

// конструктор приложения с конфигурацией по умолчанию
func New() *App {
	return &App{config: defaultAppConfig}
}
