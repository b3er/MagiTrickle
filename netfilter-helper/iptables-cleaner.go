package netfilterHelper

import (
	"fmt"
	"strings"
)

func (nh *NetfilterHelper) CleanIPTables(chainPrefix string) error {
	jumpToChainPrefix := fmt.Sprintf("-j %s", chainPrefix)
	for _, table := range []string{"nat", "mangle", "filter"} {
		chainListToDelete := make([]string, 0)

		chains, err := nh.IPTables.ListChains(table)
		if err != nil {
			return fmt.Errorf("listing chains error: %w", err)
		}

		for _, chain := range chains {
			if strings.HasPrefix(chain, chainPrefix) {
				chainListToDelete = append(chainListToDelete, chain)
				continue
			}

			rules, err := nh.IPTables.List(table, chain)
			if err != nil {
				return fmt.Errorf("listing rules error: %w", err)
			}

			for _, rule := range rules {
				if !strings.Contains(rule, jumpToChainPrefix) {
					continue
				}

				ruleSlice := strings.Split(rule, " ")
				if len(ruleSlice) < 2 || ruleSlice[0] != "-A" || ruleSlice[1] != chain {
					continue
				}

				err = nh.IPTables.Delete(table, chain, ruleSlice[2:]...)
				if err != nil {
					return fmt.Errorf("rule deletion error: %w", err)
				}
			}
		}

		for _, chain := range chainListToDelete {
			err = nh.IPTables.ClearAndDeleteChain(table, chain)
			if err != nil {
				return fmt.Errorf("deleting chain error: %w", err)
			}
		}
	}

	return nil
}
