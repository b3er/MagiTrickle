package models

type Config struct {
	App    App
	Groups []Group
}

type App struct {
	HTTPWeb   HTTPWeb
	DNSProxy  DNSProxy
	Netfilter Netfilter
	Link      []string
	LogLevel  string
}

type HTTPWeb struct {
	Enabled bool
	Host    HTTPWebServer
	Skin    string
}

type HTTPWebServer struct {
	Address string
	Port    uint16
}

type DNSProxy struct {
	Host            DNSProxyServer
	Upstream        DNSProxyServer
	DisableRemap53  bool
	DisableFakePTR  bool
	DisableDropAAAA bool
	EnableEDNS0     bool
}

type DNSProxyServer struct {
	Address string
	Port    uint16
}

type Netfilter struct {
	IPTables    IPTables
	IPSet       IPSet
	DisableIPv4 bool
	DisableIPv6 bool
}

type IPTables struct {
	ChainPrefix string
}

type IPSet struct {
	TablePrefix   string
	AdditionalTTL uint32
}
