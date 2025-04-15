package app

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	dnsMitmProxy "magitrickle/dns-mitm-proxy"
	"magitrickle/models"
	netfilterHelper "magitrickle/netfilter-helper"
	"magitrickle/records"
	"magitrickle/internal/logbuffer"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

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
	HTTPWeb: models.HTTPWeb{
		Enabled: true,
		Host: models.HTTPWebServer{
			Address: "[::]",
			Port:    8080,
		},
		Skin: "default",
	},
	Netfilter: models.Netfilter{
		IPTables: models.IPTables{
			ChainPrefix: "MT_",
		},
		IPSet: models.IPSet{
			TablePrefix:   "mt_",
			AdditionalTTL: 3600,
		},
		DisableIPv4: false,
		DisableIPv6: false,
	},
	Link:     []string{"br0"},
	LogLevel: "info",
}

// App – основная структура ядра приложения

// LogBuffer returns the ring buffer for logs.
func (a *App) LogBuffer() *logbuffer.RingBuffer {
	return a.logBuffer
}

type App struct {
	config   models.App
	dnsMITM  *dnsMitmProxy.DNSMITMProxy
	nfHelper *netfilterHelper.NetfilterHelper
	records  *records.Records
	groups   []*Group
	// Log ring buffer for API log streaming/polling
	logBuffer *logbuffer.RingBuffer
	// In-memory log level (not persisted)
	logLevel zerolog.Level
	logLevelMu sync.RWMutex
	// TODO: доделать
	enabled      atomic.Bool
	dnsOverrider *netfilterHelper.PortRemap
}

// New создаёт новый экземпляр App
func New() *App {
	a := &App{
		config:    defaultAppConfig,
		logBuffer: logbuffer.NewRingBuffer(500), // store last 500 logs (adjust as needed)
	}

	// Set initial log level from config (or info if missing)
	lvl, err := zerolog.ParseLevel(a.config.LogLevel)
	if err != nil {
		lvl = zerolog.InfoLevel
	}
	a.SetLogLevel(lvl.String())

	// Attach zerolog hook to capture logs to buffer
	log.Logger = log.Logger.Hook(logToBufferHook{app: a})

	if err := a.LoadConfig(); err != nil {
		log.Error().Err(err).Msg("failed to load config file")
	}
	return a
}

// SetLogLevel sets the in-memory log level (not persisted)
func (a *App) SetLogLevel(level string) bool {
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		return false
	}
	a.logLevelMu.Lock()
	defer a.logLevelMu.Unlock()
	a.logLevel = lvl
	zerolog.SetGlobalLevel(lvl)
	return true
}

// GetLogLevel returns the current in-memory log level
func (a *App) GetLogLevel() string {
	a.logLevelMu.RLock()
	defer a.logLevelMu.RUnlock()
	return a.logLevel.String()
}

// logToBufferHook implements zerolog.Hook to push logs into the ring buffer
// and formats them for API consumption.
type logToBufferHook struct {
	app *App
}

func (h logToBufferHook) Run(e *zerolog.Event, level zerolog.Level, msg string) {
	// Use the current local time as per user context (UTC+3)
	timestamp := time.Now().In(time.FixedZone("UTC+3", 3*60*60))
	entry := logbuffer.LogEntry{
		Time:    timestamp,
		Level:   level.String(),
		Message: msg,
	}
	// TODO: Optionally extract error from context if needed
	h.app.logBuffer.Add(entry)
}


// Config возвращает конфигурацию
func (a *App) Config() models.App {
	return a.config
}

// Groups возвращает список групп
func (a *App) Groups() []*Group {
	return a.groups
}

// ClearGroups отключает все группы и очищает список
func (a *App) ClearGroups() {
	for _, g := range a.groups {
		_ = g.Disable()
	}
	a.groups = a.groups[:0]
}

// AddGroup добавляет новую группу
func (a *App) AddGroup(groupModel *models.Group) error {
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

	// если приложение уже запущено – включаем группу и выполняем синхронизацию
	if a.enabled.Load() {
		if err = grp.Enable(); err != nil {
			return fmt.Errorf("failed to enable group: %w", err)
		}
		if err = grp.Sync(); err != nil {
			return fmt.Errorf("failed to sync group: %w", err)
		}
	}
	return nil
}

// RemoveGroupByIndex удаляет группу по индексу
func (a *App) RemoveGroupByIndex(idx int) {
	a.groups = append(a.groups[:idx], a.groups[idx+1:]...)
}

// ListInterfaces возвращает список сетевых интерфейсов, удовлетворяющих заданным критериям
func (a *App) ListInterfaces() ([]net.Interface, error) {
	var filteredInterfaces []net.Interface

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagPointToPoint == 0 {
			continue
		}
		filteredInterfaces = append(filteredInterfaces, iface)
	}

	return filteredInterfaces, nil
}

// DnsOverrider возвращает dnsOverrider
func (a *App) DnsOverrider() *netfilterHelper.PortRemap {
	return a.dnsOverrider
}
