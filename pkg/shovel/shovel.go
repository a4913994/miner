package shovel

import (
	"github.com/a4913994/miner/pkg/errfmt"
	"github.com/a4913994/miner/pkg/shovel/ebpf/probes"
	bpf "github.com/aquasecurity/libbpfgo"
)

// Shovel for miner is used to trace system calls and system events using eBPF
type Shovel struct {
	config Config

	bpfModule *bpf.Module
	probes    probes.Probes
}

// New creates a new Shovel instance based on a given valid Config. It is
// expected that it won't cause external system side effects (reads, writes,
// etc.)
func New(c Config) *Shovel {
	return &Shovel{
		config: c,
	}
}

// Init initialize tracee instance and it's various subsystems, potentially
// performing external system operations to initialize them. NOTE: any
// initialization logic, especially one that causes side effects, should go
// here and not New().
func (s *Shovel) Init() error {
	return s.initBPF()
}

func (s *Shovel) initBPF() error {
	var err error
	newModuleArgs := bpf.NewModuleArgs{
		KConfigFilePath: s.config.KConfigFilePath,
		BTFObjPath:      s.config.BTFObjPath,
		BPFObjBuff:      s.config.BPFObjBytes,
	}

	// Open the eBPF object file (create a new module)
	s.bpfModule, err = bpf.NewModuleFromBufferArgs(newModuleArgs)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Initialize probes
	s.probes = probes.NewProbes(s.bpfModule)
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Load the eBPF object into kernel
	err = s.bpfModule.BPFLoadObject()
	if err != nil {
		return errfmt.WrapError(err)
	}

	// Populate eBPF maps with initial data
	//err = s.populateBPFMaps()
	//if err != nil {
	//	return errfmt.WrapError(err)
	//}

	return err
}

func (s *Shovel) Excavate(point probes.TracePoint) error {
	return s.probes.Attach(point)
}
