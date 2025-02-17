package main

import (
	"fmt"
	"log"
	"os"

	magitrickleAPI "magitrickle/pkg/magitrickle-api"

	"github.com/spf13/cobra"
)

var magitrickleClient magitrickleAPI.Client

func init() {
	magitrickleClient = magitrickleAPI.NewClient()
}

func main() {
	rootCmd := &cobra.Command{}
	rootCmd.AddCommand(appCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func appCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "app",
		Short: "Application commands",
	}
	cmd.AddCommand(appHookCmd())
	return cmd
}

func appHookCmd() *cobra.Command {
	hookCmd := &cobra.Command{
		Use:   "hook",
		Short: "Emit hook",
	}
	hookCmd.AddCommand(appHookNetfilterDCmd())
	return hookCmd
}

func appHookNetfilterDCmd() *cobra.Command {
	var ipttype string
	var table string
	cmd := &cobra.Command{
		Use:   "netfilter.d",
		Short: "netfilter.d hook",
		Run: func(cmd *cobra.Command, args []string) {
			err := magitrickleClient.NetfilterDHook(ipttype, table)
			if err != nil {
				log.Fatalf("executing hook error: %v", err)
			}
		},
	}
	cmd.Flags().StringVar(&ipttype, "type", "", "iptables type")
	cmd.Flags().StringVar(&table, "table", "", "iptables table")
	return cmd
}
