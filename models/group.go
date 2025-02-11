package models

type Group struct {
	ID         ID      `yaml:"id"`
	Name       string  `yaml:"name"`
	Interface  string  `yaml:"interface"`
	FixProtect bool    `yaml:"fixProtect"`
	Rules      []*Rule `yaml:"rules"`
}
