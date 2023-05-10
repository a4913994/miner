package cpu

import (
	"sync"
	"time"

	logger "github.com/a4913994/miner/pkg/log"
)

var (
	bpfObj []byte

	cpuProgramFd uint64 = 0
)

const (
	// The maximum number of stack frames we can store in the BPF map.
	stackDepth = 127

	programName = "profile_cpu"
)

type CPU struct {
	logger *logger.Logger

	lock *sync.RWMutex

	// profilingDuration is the duration for which the CPU profiler should run.
	profilingDuration time.Duration
	// profilingSampleFrequency is the frequency at which the CPU profiler should sample the CPU.
	profilingSampleFrequency uint64

	processInfoManager interface{}
	addressNormalizer  interface{}
	symbolize          interface{}
	profileWriter      interface{}
}
