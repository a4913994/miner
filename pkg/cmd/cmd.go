package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/a4913994/miner/pkg/cmd/runner"
	logger "github.com/a4913994/miner/pkg/log"
)

type MinerOptions struct {
	Arguments []string

	IOStreams
}

// NewDefaultMinerCommand creates the `miner` command with default arguments.
func NewDefaultMinerCommand() *cobra.Command {
	return NewDefaultMinerCommandWithArgs(MinerOptions{
		Arguments: os.Args,
		IOStreams: IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr},
	})
}

// NewDefaultMinerCommandWithArgs creates the `miner` command and its nested children commands for the default case with default arguments.
func NewDefaultMinerCommandWithArgs(o MinerOptions) *cobra.Command {
	cmd := NewMinerCommand(o)
	return cmd
}

// NewMinerCommand creates the `miner` command and its nested children commands.
func NewMinerCommand(o MinerOptions) *cobra.Command {

	cmds := &cobra.Command{
		Use:   "miner",
		Short: "Miner collect host cpu and memory usage.",
		Long: `
Miner collect host cpu and memory usage.

Find more information at:
	https://github.com/a4913994/miner
`,
		Run: func(cmd *cobra.Command, args []string) {

			r := runner.New()

			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			err := r.Run(ctx)
			if err != nil {
				logger.Fatalf("Miner runner failed", "error", err)
				os.Exit(1)
			}
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	//flags := cmds.Flags()

	return cmds
}
