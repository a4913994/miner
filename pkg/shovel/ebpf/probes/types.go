package probes

// TracePoint is a type of trace event name.
type TracePoint uint16

const (
	SysMmap TracePoint = iota
	SysEnter
	SysExit
	SyscallEnterInternal
	SyscallExitInternal
	SchedProcessFork
	SchedProcessExec
	SchedProcessExit
	SchedProcessFree
	SchedSwitch
	DoExit
	CapCapable
	VfsWrite
	VfsWriteRet
	VfsWriteV
	VfsWriteVRet
	KernelWrite
	KernelWriteRet
	CgroupAttachTask
	CgroupMkdir
	CgroupRmdir
	RegisterKprobe
	RegisterKprobeRet
	DeviceAdd
	DoInitModule
	DoInitModuleRet
	SockAllocFile
	SockAllocFileRet
	DoMmap
	DoMmapRet
	VfsRead
	VfsReadRet
	VfsReadV
	VfsReadVRet
	VfsUtimes
	UtimesCommon
	DoTruncate
	FileUpdateTime
	FileUpdateTimeRet
	FileModified
	FileModifiedRet
	FdInstall
	FilpClose
	InotifyFindInode
	InotifyFindInodeRet
	BpfCheck
	ExecBinprm
	ExecBinprmRet
)

// probeType is a type of probe.
type probeType uint8

const (
	// github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-kp
	kprobe = iota
	// github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-kp
	kretprobe
	// github.com/iovisor/bcc/blob/master/docs/reference_guide.md#3-tracep
	tracepoint
	// github.com/iovisor/bcc/blob/master/docs/reference_guide.md#7-raw-tracep
	rawTracepoint
)
