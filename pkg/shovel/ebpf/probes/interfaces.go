package probes

import bpf "github.com/aquasecurity/libbpfgo"

// Probes
//
// NOTE: keeping both (Probes and Probe) interfaces with variadic args on
//
//	**purpose** until we define real use cases, by extending supported
//	"probes" types (trace, tc, socket, xdp, tunnel, cgroup, ...) **
type Probes interface {
	Attach(t TracePoint, args ...any) error
	Detach(t TracePoint, args ...any) error
	DetachAll() error
}

type Probe interface {
	attach(module *bpf.Module, args ...any) error
	detach(...any) error
	//autoload(module *bpf.Module, autoload bool) error
}
