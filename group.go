package main

import (
	"fmt"
	"net"
	"time"

	"kvas2-go/models"
	"kvas2-go/netfilter-helper"

	"github.com/coreos/go-iptables/iptables"
)

type Group struct {
	*models.Group

	Enabled bool

	iptables        *iptables.IPTables
	ipset           *netfilterHelper.IPSet
	ifaceToIPSetNAT *netfilterHelper.IfaceToIPSet
}

func (g *Group) AddIPv4(address net.IP, ttl time.Duration) error {
	ttlSeconds := uint32(ttl.Seconds())
	return g.ipset.AddIP(address, &ttlSeconds)
}

func (g *Group) DelIPv4(address net.IP) error {
	return g.ipset.Del(address)
}

func (g *Group) ListIPv4() (map[string]*uint32, error) {
	return g.ipset.List()
}

func (g *Group) Enable() error {
	if g.Enabled {
		return nil
	}
	defer func() {
		if !g.Enabled {
			_ = g.Disable()
		}
	}()

	if g.FixProtect {
		err := g.iptables.AppendUnique("filter", "_NDM_SL_FORWARD", "-o", g.Interface, "-m", "state", "--state", "NEW", "-j", "_NDM_SL_PROTECT")
		if err != nil {
			return fmt.Errorf("failed to fix protect: %w", err)
		}
	}

	err := g.ifaceToIPSetNAT.Enable()
	if err != nil {
		return err
	}

	g.Enabled = true

	return nil
}

func (g *Group) Disable() []error {
	var errs []error

	if !g.Enabled {
		return nil
	}

	err := g.ifaceToIPSetNAT.Disable()
	if err != nil {
		errs = append(errs, err...)
	}

	g.Enabled = false

	return errs
}
