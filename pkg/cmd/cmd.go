package cmd

import (
	"github.com/spf13/cobra"
	"os"
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
			_ = cmd.Help()
		},
	}

	//flags := cmds.Flags()

	return cmds
}
