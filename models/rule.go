package models

import (
	"regexp"

	"github.com/IGLOU-EU/go-wildcard/v2"
	"github.com/google/uuid"
)

type Rule struct {
	ID     uuid.UUID
	Name   string
	Type   string
	Rule   string
	Enable bool
}

func (d *Rule) IsEnabled() bool {
	return d.Enable
}

func (d *Rule) IsMatch(domainName string) bool {
	switch d.Type {
	case "wildcard":
		return wildcard.Match(d.Rule, domainName)
	case "regex":
		ok, _ := regexp.MatchString(d.Rule, domainName)
		return ok
	case "plaintext":
		return domainName == d.Rule
	}
	return false
}
