package initialize

import (
	"os"

	"github.com/a4913994/miner/embed"
	"github.com/a4913994/miner/pkg/errfmt"
	logger "github.com/a4913994/miner/pkg/log"
	"github.com/a4913994/miner/pkg/shovel"
)

// BpfObject sets up and configures a BPF object for tracing and monitoring
// system events within the kernel. It takes pointers to tracee.Config,
// helpers.KernelConfig, and helpers.OSInfo structures, as well as an
// installation path and a version string. The function unpacks the CO-RE eBPF
// object binary, checks if BTF is enabled, unpacks the BTF file from BTF Hub if
// necessary, and assigns the kernel configuration and BPF object bytes.
func BpfObject(config *shovel.Config) error {
	btfFilePath, err := checkEnvPath("TRACE_BTF_FILE")
	if btfFilePath == "" && err != nil {
		return errfmt.WrapError(err)
	}
	if btfFilePath != "" {
		logger.Debugf("BTF", "BTF environment variable set", "path", btfFilePath)
		config.BTFObjPath = btfFilePath
	}

	bpfBytes, err := unpackCOREBinary()
	if err != nil {
		return errfmt.Errorf("could not unpack CO-RE eBPF object: %v", err)
	}

	config.BPFObjBytes = bpfBytes

	return nil
}

func checkEnvPath(env string) (string, error) {
	filePath, _ := os.LookupEnv(env)
	if filePath != "" {
		_, err := os.Stat(filePath)
		if err != nil {
			return "", errfmt.Errorf("could not open %s %s", env, filePath)
		}
		return filePath, nil
	}
	return "", nil
}

func unpackCOREBinary() ([]byte, error) {
	b, err := embed.BPFBundleInjected.ReadFile("dist/tracee.bpf.o")
	if err != nil {
		return nil, err
	}

	logger.Debugf("Unpacked CO:RE bpf object file into memory")

	return b, nil
}
