package runner

import (
	"context"

	"github.com/a4913994/miner/pkg/cmd/initialize"
	"github.com/a4913994/miner/pkg/errfmt"
	"github.com/a4913994/miner/pkg/shovel"
)

type Runner struct {
	c shovel.Config
}

func New() *Runner {
	return &Runner{}
}

func (r *Runner) init() error {
	cfg := shovel.Config{}
	// Decide BTF & BPF files to use (based in the kconfig, release & environment info)
	err := initialize.BpfObject(&cfg)
	if err != nil {
		return errfmt.Errorf("failed preparing BPF object: %v", err)
	}
	r.c = cfg

	return nil
}

func (r *Runner) Run(ctx context.Context) error {
	s := shovel.New(r.c)
	err := s.Init()
	if err != nil {
		return errfmt.Errorf("error initializing Tracee: %v", err)
	}
	return nil
}
