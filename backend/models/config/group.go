package config

import (
	"magitrickle/api/types"
)

type Group struct {
	ID         types.ID `yaml:"id"`
	Name       string   `yaml:"name"`
	Color      string   `yaml:"color"`
	Interface  string   `yaml:"interface"`
	FixProtect bool     `yaml:"fixProtect"`
	Rules      []Rule   `yaml:"rules"`
}
