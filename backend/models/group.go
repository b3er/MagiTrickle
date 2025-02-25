package models

import (
	"magitrickle/pkg/magitrickle-api/types"
)

type Group struct {
	ID         types.ID
	Name       string
	Color      string
	Interface  string
	FixProtect bool
	Rules      []*Rule
}
