package models

import (
	"regexp"
	"strings"

	"github.com/IGLOU-EU/go-wildcard/v2"
)

type Rule struct {
	ID     ID     `yaml:"id"`
	Name   string `yaml:"name"`
	Type   string `yaml:"type"`
	Rule   string `yaml:"rule"`
	Enable bool   `yaml:"enable"`
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
	case "domain":
		return domainName == d.Rule
	case "namespace":
		if domainName == d.Rule {
			return true
		}
		return strings.HasSuffix(domainName, "."+d.Rule)
	}
	return false
}
