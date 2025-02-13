package models

type ConfigFile struct {
	AppConfig AppConfig `yaml:"appConfig"`
	Groups    []Group   `yaml:"groups"`
}

type AppConfig struct {
	LogLevel               string `yaml:"logLevel"`
	AdditionalTTL          uint32 `yaml:"additionalTTL"`
	ChainPrefix            string `yaml:"chainPrefix"`
	IPSetPrefix            string `yaml:"ipsetPrefix"`
	LinkName               string `yaml:"linkName"`
	TargetDNSServerAddress string `yaml:"targetDNSServerAddress"`
	TargetDNSServerPort    uint16 `yaml:"targetDNSServerPort"`
	ListenDNSPort          uint16 `yaml:"listenDNSPort"`
}
