package shovel

type Config struct {
	// KConfigFilePath is the path to the kernel config file
	KConfigFilePath string
	// BTFObjPath is the path to the BTF object file
	BTFObjPath string
	// BPFObjBytes is the BPF object file bytes
	BPFObjBytes []byte
}
