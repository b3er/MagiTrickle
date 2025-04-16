package config

type Config struct {
	ConfigVersion string   `yaml:"configVersion"`
	App           *App     `yaml:"app"`
	Groups        *[]Group `yaml:"groups"`
}

type App struct {
	HTTPWeb   *HTTPWeb   `yaml:"httpWeb"`
	DNSProxy  *DNSProxy  `yaml:"dnsProxy"`
	Netfilter *Netfilter `yaml:"netfilter"`
	Link      *[]string  `yaml:"link"`
	LogLevel  *string    `yaml:"logLevel"`
}

type HTTPWeb struct {
	Enabled *bool          `yaml:"enabled"`
	Host    *HTTPWebServer `yaml:"host"`
	Skin    *string        `yaml:"skin"`
}

type HTTPWebServer struct {
	Address *string `yaml:"address"`
	Port    *uint16 `yaml:"port"`
}

type DNSProxy struct {
	// Host is kept for backward compatibility but will be deprecated
	Host *DNSProxyServer `yaml:"host"`
	// Hosts is a list of DNS proxy servers to listen on
	Hosts           *[]DNSProxyServer `yaml:"hosts"`
	Upstream        *DNSProxyServer   `yaml:"upstream"`
	DisableRemap53  *bool             `yaml:"disableRemap53"`
	DisableFakePTR  *bool             `yaml:"disableFakePTR"`
	DisableDropAAAA *bool             `yaml:"disableDropAAAA"`
	EnableEDNS0     *bool             `yaml:"enableEDNS0"`
}

type DNSProxyServer struct {
	Address *string `yaml:"address"`
	Port    *uint16 `yaml:"port"`
}

type Netfilter struct {
	IPTables    *IPTables `yaml:"iptables"`
	IPSet       *IPSet    `yaml:"ipset"`
	DisableIPv4 *bool     `yaml:"disableIPv4"`
	DisableIPv6 *bool     `yaml:"disableIPv6"`
}

type IPTables struct {
	ChainPrefix *string `yaml:"chainPrefix"`
}

type IPSet struct {
	TablePrefix   *string `yaml:"tablePrefix"`
	AdditionalTTL *uint32 `yaml:"additionalTTL"`
}
