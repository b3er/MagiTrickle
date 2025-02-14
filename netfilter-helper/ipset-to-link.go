package netfilterHelper

import (
	"fmt"
	"net"
	"strconv"

	"github.com/coreos/go-iptables/iptables"
	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

type IPSetToLink struct {
	IPTables  *iptables.IPTables
	ChainName string
	IfaceName string
	IPSetName string

	enabled bool
	mark    uint32
	table   int
	ipRule  *netlink.Rule
	ipRoute *netlink.Route
}

func (r *IPSetToLink) insertIPTablesRules(table string) error {
	var err error

	if table == "" || table == "mangle" {
		err = r.IPTables.NewChain("mangle", r.ChainName)
		if err != nil {
			// If not "AlreadyExists"
			if eerr, eok := err.(*iptables.Error); !(eok && eerr.ExitStatus() == 1) {
				return fmt.Errorf("failed to create chain: %w", err)
			}
		}

		for _, iptablesArgs := range [][]string{
			{"-j", "MARK", "--set-mark", strconv.Itoa(int(r.mark))},
			{"-j", "CONNMARK", "--save-mark"},
		} {
			err = r.IPTables.AppendUnique("mangle", r.ChainName, iptablesArgs...)
			if err != nil {
				return fmt.Errorf("failed to append rule: %w", err)
			}
		}

		err = r.IPTables.InsertUnique("mangle", "PREROUTING", 1, "-m", "set", "--match-set", r.IPSetName, "dst", "-j", r.ChainName)
		if err != nil {
			return fmt.Errorf("failed to append rule to PREROUTING: %w", err)
		}
	}

	if table == "" || table == "nat" {
		err = r.IPTables.NewChain("nat", r.ChainName)
		if err != nil {
			// If not "AlreadyExists"
			if eerr, eok := err.(*iptables.Error); !(eok && eerr.ExitStatus() == 1) {
				return fmt.Errorf("failed to create chain: %w", err)
			}
		}

		err = r.IPTables.AppendUnique("nat", r.ChainName, "-j", "MASQUERADE")
		if err != nil {
			return fmt.Errorf("failed to create rule: %w", err)
		}

		err = r.IPTables.AppendUnique("nat", "POSTROUTING", "-m", "set", "--match-set", r.IPSetName, "dst", "-j", r.ChainName)
		if err != nil {
			return fmt.Errorf("failed to append rule to POSTROUTING: %w", err)
		}
	}

	return nil
}

func (r *IPSetToLink) deleteIPTablesRules() []error {
	var errs []error

	err := r.IPTables.DeleteIfExists("mangle", "PREROUTING", "-m", "set", "--match-set", r.IPSetName, "dst", "-j", r.ChainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to unlinking chain: %w", err))
	}

	err = r.IPTables.ClearAndDeleteChain("mangle", r.ChainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to delete chain: %w", err))
	}

	err = r.IPTables.DeleteIfExists("nat", "POSTROUTING", "-m", "set", "--match-set", r.IPSetName, "dst", "-j", r.ChainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to unlinking chain: %w", err))
	}

	err = r.IPTables.ClearAndDeleteChain("nat", r.ChainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to delete chain: %w", err))
	}

	return errs
}

func (r *IPSetToLink) insertIPRule() error {
	rule := netlink.NewRule()
	rule.Mark = r.mark
	rule.Table = r.table
	_ = netlink.RuleDel(rule)
	err := netlink.RuleAdd(rule)
	if err != nil {
		return fmt.Errorf("error while mapping mark with table: %w", err)
	}
	r.ipRule = rule

	log.Trace().Int("table", r.table).Int("mark", int(r.mark)).Msg("using ip table and mark")

	return nil
}

func (r *IPSetToLink) deleteIPRule() []error {
	if r.ipRule == nil {
		return nil
	}

	err := netlink.RuleDel(r.ipRule)
	if err != nil {
		return []error{fmt.Errorf("error while deleting rule: %w", err)}
	}
	r.ipRule = nil
	return nil
}

func (r *IPSetToLink) insertIPRoute() error {
	// Find interface
	iface, err := netlink.LinkByName(r.IfaceName)
	if err != nil {
		// TODO: Нормально отлавливать ошибку
		if err.Error() == "Link not found" {
			log.Debug().Str("iface", r.IfaceName).Msg("interface not found (waiting for it to exist)")
			return nil
		}
		return fmt.Errorf("error while getting interface: %w", err)
	}

	// Mapping iface with table
	route := &netlink.Route{
		LinkIndex: iface.Attrs().Index,
		Table:     r.table,
		Dst:       &net.IPNet{IP: []byte{0, 0, 0, 0}, Mask: []byte{0, 0, 0, 0}},
	}
	// Delete rule if exists
	err = netlink.RouteAdd(route)
	if err != nil {
		// TODO: Нормально отлавливать ошибку
		if err.Error() == "file exists" {
			return nil
		}
		return fmt.Errorf("error while mapping iface with table: %w", err)
	}
	r.ipRoute = route

	return nil
}

func (r *IPSetToLink) deleteIPRoute() []error {
	if r.ipRoute == nil {
		return nil
	}

	err := netlink.RouteDel(r.ipRoute)
	if err != nil {
		return []error{fmt.Errorf("error while deleting route: %w", err)}
	}
	r.ipRoute = nil
	return nil
}

func (r *IPSetToLink) getUnusedMarkAndTable() (mark uint32, table int, err error) {
	// Find unused mark and table
	markMap := make(map[uint32]struct{})
	tableMap := map[int]struct{}{0: {}, 253: {}, 254: {}, 255: {}}

	rules, err := netlink.RuleList(nl.FAMILY_ALL)
	if err != nil {
		return 0, 0, fmt.Errorf("error while getting rules: %w", err)
	}
	for _, rule := range rules {
		markMap[rule.Mark] = struct{}{}
		tableMap[rule.Table] = struct{}{}
	}

	routes, err := netlink.RouteListFiltered(nl.FAMILY_ALL, &netlink.Route{}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return 0, 0, fmt.Errorf("error while getting routes: %w", err)
	}
	for _, route := range routes {
		tableMap[route.Table] = struct{}{}
	}

	for table = 0; table < 0x7ffffffe; table++ {
		if _, exists := tableMap[table]; !exists {
			break
		}
	}

	for mark = 0; mark < 0xfffffffe; mark++ {
		if _, exists := markMap[mark]; !exists {
			break
		}
	}

	return mark, table, nil
}

func (r *IPSetToLink) enable() error {
	// Release used mark and table
	r.Disable()

	var err error
	r.mark, r.table, err = r.getUnusedMarkAndTable()
	if err != nil {
		return err
	}

	err = r.IPTables.ClearChain("mangle", r.ChainName)
	if err != nil {
		return fmt.Errorf("failed to clear chain: %w", err)
	}

	err = r.IPTables.ClearChain("nat", r.ChainName)
	if err != nil {
		return fmt.Errorf("failed to clear chain: %w", err)
	}

	// IPTables rules
	err = r.insertIPTablesRules("")
	if err != nil {
		return err
	}

	err = r.insertIPRule()
	if err != nil {
		return err
	}

	err = r.insertIPRoute()
	if err != nil {
		return err
	}

	r.enabled = true
	return nil
}

func (r *IPSetToLink) Enable() error {
	if r.enabled {
		return nil
	}

	err := r.enable()
	if err != nil {
		r.Disable()
		return err
	}

	return nil
}

func (r *IPSetToLink) Disable() []error {
	var errs []error
	errs = append(errs, r.deleteIPRoute()...)
	errs = append(errs, r.deleteIPRule()...)
	errs = append(errs, r.deleteIPTablesRules()...)

	r.enabled = false
	return errs
}

func (r *IPSetToLink) NetfilterDHook(table string) error {
	if !r.enabled {
		return nil
	}
	return r.insertIPTablesRules(table)
}

func (r *IPSetToLink) LinkUpdateHook(event netlink.LinkUpdate) error {
	if !r.enabled || event.Change != 1 || event.Link.Attrs().Name != r.IfaceName {
		return nil
	}
	return r.insertIPRoute()
}

func (nh *NetfilterHelper) IPSetToLink(name string, ifaceName, ipsetName string) *IPSetToLink {
	return &IPSetToLink{
		IPTables:  nh.IPTables,
		ChainName: name,
		IfaceName: ifaceName,
		IPSetName: ipsetName,
	}
}
