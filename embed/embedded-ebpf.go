package embed

import (
	"embed"
)

//go:embed "dist/trace.bpf.o"

var BPFBundleInjected embed.FS
