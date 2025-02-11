package netfilterHelper

import (
	"fmt"
	"net"
	"strconv"

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
)

type PortRemap struct {
	IPTables  *iptables.IPTables
	ChainName string
	Addresses []netlink.Addr
	From      uint16
	To        uint16

	enabled bool
}

func (r *PortRemap) insertIPTablesRules(table string) error {
	if table == "" || table == "nat" {
		err := r.IPTables.NewChain("nat", r.ChainName)
		if err != nil {
			// If not "AlreadyExists"
			if eerr, eok := err.(*iptables.Error); !(eok && eerr.ExitStatus() == 1) {
				return fmt.Errorf("failed to create chain: %w", err)
			}
		}

		for _, addr := range r.Addresses {
			if !((r.IPTables.Proto() == iptables.ProtocolIPv4 && len(addr.IP) == net.IPv4len) || (r.IPTables.Proto() == iptables.ProtocolIPv6 && len(addr.IP) == net.IPv6len)) {
				continue
			}

			for _, iptablesArgs := range [][]string{
				{"-p", "tcp", "-d", addr.IP.String(), "--dport", strconv.Itoa(int(r.From)), "-j", "DNAT", "--to-destination", fmt.Sprintf(":%d", r.To)},
				{"-p", "udp", "-d", addr.IP.String(), "--dport", strconv.Itoa(int(r.From)), "-j", "DNAT", "--to-destination", fmt.Sprintf(":%d", r.To)},
			} {
				err = r.IPTables.AppendUnique("nat", r.ChainName, iptablesArgs...)
				if err != nil {
					return fmt.Errorf("failed to append rule: %w", err)
				}
			}
		}

		err = r.IPTables.InsertUnique("nat", "PREROUTING", 1, "-j", r.ChainName)
		if err != nil {
			return fmt.Errorf("failed to linking chain: %w", err)
		}
	}

	return nil
}

func (r *PortRemap) deleteIPTablesRules() []error {
	var errs []error

	err := r.IPTables.DeleteIfExists("nat", "PREROUTING", "-j", r.ChainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to unlinking chain: %w", err))
	}

	err = r.IPTables.ClearAndDeleteChain("nat", r.ChainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to delete chain: %w", err))
	}

	return errs
}

func (r *PortRemap) enable() error {
	err := r.insertIPTablesRules("")
	if err != nil {
		return err
	}

	r.enabled = true
	return nil
}

func (r *PortRemap) Enable() error {
	if r.enabled {
		return nil
	}

	err := r.IPTables.ClearChain("nat", r.ChainName)
	if err != nil {
		return fmt.Errorf("failed to clear chain: %w", err)
	}

	err = r.enable()
	if err != nil {
		r.Disable()
		return err
	}

	return nil
}

func (r *PortRemap) Disable() []error {
	errs := r.deleteIPTablesRules()
	r.enabled = false
	return errs
}

func (r *PortRemap) NetfilterDHook(table string) error {
	if !r.enabled {
		return nil
	}
	return r.insertIPTablesRules(table)
}

func (nh *NetfilterHelper) PortRemap(name string, from, to uint16, addr []netlink.Addr) *PortRemap {
	return &PortRemap{
		IPTables:  nh.IPTables,
		ChainName: name,
		Addresses: addr,
		From:      from,
		To:        to,
	}
}
