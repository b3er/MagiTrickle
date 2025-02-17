package models

import (
	"magitrickle/pkg/magitrickle-api/types"
)

type Group struct {
	ID         types.ID `yaml:"id"`
	Name       string   `yaml:"name"`
	Interface  string   `yaml:"interface"`
	FixProtect bool     `yaml:"fixProtect"`
	Rules      []*Rule  `yaml:"rules"`
}
