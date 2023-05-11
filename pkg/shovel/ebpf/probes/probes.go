package probes

import (
	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/a4913994/miner/pkg/errfmt"
)

var _ Probes = (*probes)(nil)

type probes struct {
	module *bpf.Module
	probes map[TracePoint]Probe
}

// NewProbes creates a new probes instance
func NewProbes(module *bpf.Module) Probes {
	allProbes := make(map[TracePoint]Probe)
	// ======== Debug ========
	allProbes[SysMmap] = &traceProbe{eventName: "sys_mmap", probeType: kprobe, programName: "kprobe__sys_mmap"}

	// ======== RawTracepoint probes ========
	allProbes[SysEnter] = &traceProbe{eventName: "raw_syscalls:sys_enter", probeType: rawTracepoint, programName: "trace_sys_enter"}
	allProbes[SysExit] = &traceProbe{eventName: "raw_syscalls:sys_exit", probeType: rawTracepoint, programName: "trace_sys_exit"}
	allProbes[SyscallEnterInternal] = &traceProbe{eventName: "raw_syscalls:sys_enter", probeType: rawTracepoint, programName: "tracepoint__raw_syscalls__sys_enter"}
	allProbes[SyscallExitInternal] = &traceProbe{eventName: "raw_syscalls:sys_exit", probeType: rawTracepoint, programName: "tracepoint__raw_syscalls__sys_exit"}

	allProbes[SchedProcessFork] = &traceProbe{eventName: "sched:sched_process_fork", probeType: rawTracepoint, programName: "tracepoint__sched__sched_process_fork"}
	allProbes[SchedProcessExec] = &traceProbe{eventName: "sched:sched_process_exec", probeType: rawTracepoint, programName: "tracepoint__sched__sched_process_exec"}
	allProbes[SchedProcessExit] = &traceProbe{eventName: "sched:sched_process_exit", probeType: rawTracepoint, programName: "tracepoint__sched__sched_process_exit"}
	allProbes[SchedProcessFree] = &traceProbe{eventName: "sched:sched_process_free", probeType: rawTracepoint, programName: "tracepoint__sched__sched_process_free"}
	allProbes[SchedSwitch] = &traceProbe{eventName: "sched:sched_switch", probeType: rawTracepoint, programName: "tracepoint__sched__sched_switch"}

	allProbes[CgroupAttachTask] = &traceProbe{eventName: "cgroup:cgroup_attach_task", probeType: rawTracepoint, programName: "tracepoint__cgroup__cgroup_attach_task"}
	allProbes[CgroupMkdir] = &traceProbe{eventName: "cgroup:cgroup_mkdir", probeType: rawTracepoint, programName: "tracepoint__cgroup__cgroup_mkdir"}
	allProbes[CgroupRmdir] = &traceProbe{eventName: "cgroup:cgroup_rmdir", probeType: rawTracepoint, programName: "tracepoint__cgroup__cgroup_rmdir"}

	// ======== kprobe/kretprobe probes ========
	allProbes[DoExit] = &traceProbe{eventName: "do_exit", probeType: kprobe, programName: "trace_do_exit"}
	allProbes[CapCapable] = &traceProbe{eventName: "cap_capable", probeType: kprobe, programName: "trace_cap_capable"}
	allProbes[VfsWrite] = &traceProbe{eventName: "vfs_write", probeType: kprobe, programName: "trace_vfs_write"}
	allProbes[VfsWriteRet] = &traceProbe{eventName: "vfs_write", probeType: kretprobe, programName: "trace_ret_vfs_write"}
	allProbes[VfsWriteV] = &traceProbe{eventName: "vfs_writev", probeType: kprobe, programName: "trace_vfs_writev"}
	allProbes[VfsWriteVRet] = &traceProbe{eventName: "vfs_writev", probeType: kretprobe, programName: "trace_ret_vfs_writev"}
	allProbes[KernelWrite] = &traceProbe{eventName: "__kernel_write", probeType: kprobe, programName: "trace_kernel_write"}
	allProbes[KernelWriteRet] = &traceProbe{eventName: "__kernel_write", probeType: kretprobe, programName: "trace_ret_kernel_write"}
	allProbes[RegisterKprobe] = &traceProbe{eventName: "register_kprobe", probeType: kprobe, programName: "trace_register_kprobe"}
	allProbes[RegisterKprobeRet] = &traceProbe{eventName: "register_kprobe", probeType: kretprobe, programName: "trace_ret_register_kprobe"}
	allProbes[DeviceAdd] = &traceProbe{eventName: "device_add", probeType: kprobe, programName: "trace_device_add"}
	allProbes[DoInitModule] = &traceProbe{eventName: "do_init_module", probeType: kprobe, programName: "trace_do_init_module"}
	allProbes[DoInitModuleRet] = &traceProbe{eventName: "do_init_module", probeType: kretprobe, programName: "trace_ret_do_init_module"}
	allProbes[SockAllocFile] = &traceProbe{eventName: "sock_alloc_file", probeType: kprobe, programName: "trace_sock_alloc_file"}
	allProbes[SockAllocFileRet] = &traceProbe{eventName: "sock_alloc_file", probeType: kretprobe, programName: "trace_ret_sock_alloc_file"}
	allProbes[DoMmap] = &traceProbe{eventName: "do_mmap", probeType: kprobe, programName: "trace_do_mmap"}
	allProbes[DoMmapRet] = &traceProbe{eventName: "do_mmap", probeType: kretprobe, programName: "trace_ret_do_mmap"}
	allProbes[VfsRead] = &traceProbe{eventName: "vfs_read", probeType: kprobe, programName: "trace_vfs_read"}
	allProbes[VfsReadRet] = &traceProbe{eventName: "vfs_read", probeType: kretprobe, programName: "trace_ret_vfs_read"}
	allProbes[VfsReadV] = &traceProbe{eventName: "vfs_readv", probeType: kprobe, programName: "trace_vfs_readv"}
	allProbes[VfsReadVRet] = &traceProbe{eventName: "vfs_readv", probeType: kretprobe, programName: "trace_ret_vfs_readv"}
	allProbes[VfsUtimes] = &traceProbe{eventName: "vfs_utimes", probeType: kprobe, programName: "trace_vfs_utimes"}
	allProbes[UtimesCommon] = &traceProbe{eventName: "utimes_common", probeType: kprobe, programName: "trace_utimes_common"}
	allProbes[DoTruncate] = &traceProbe{eventName: "do_truncate", probeType: kprobe, programName: "trace_do_truncate"}
	allProbes[FileUpdateTime] = &traceProbe{eventName: "file_update_time", probeType: kprobe, programName: "trace_file_update_time"}
	allProbes[FileUpdateTimeRet] = &traceProbe{eventName: "file_update_time", probeType: kretprobe, programName: "trace_ret_file_update_time"}
	allProbes[FileModified] = &traceProbe{eventName: "file_modified", probeType: kprobe, programName: "trace_file_modified"}
	allProbes[FileModifiedRet] = &traceProbe{eventName: "file_modified", probeType: kretprobe, programName: "trace_ret_file_modified"}
	allProbes[FdInstall] = &traceProbe{eventName: "fd_install", probeType: kprobe, programName: "trace_fd_install"}
	allProbes[FilpClose] = &traceProbe{eventName: "filp_close", probeType: kprobe, programName: "trace_filp_close"}
	allProbes[InotifyFindInode] = &traceProbe{eventName: "inotify_find_inode", probeType: kprobe, programName: "trace_inotify_find_inode"}
	allProbes[InotifyFindInodeRet] = &traceProbe{eventName: "inotify_find_inode", probeType: kretprobe, programName: "trace_ret_inotify_find_inode"}
	allProbes[BpfCheck] = &traceProbe{eventName: "bpf_check", probeType: kprobe, programName: "trace_bpf_check"}
	allProbes[ExecBinprm] = &traceProbe{eventName: "exec_binprm", probeType: kprobe, programName: "trace_exec_binprm"}
	allProbes[ExecBinprmRet] = &traceProbe{eventName: "exec_binprm", probeType: kretprobe, programName: "trace_ret_exec_binprm"}

	return &probes{
		probes: allProbes,
		module: module,
	}
}

func (p *probes) Attach(t TracePoint, args ...any) error {
	if _, ok := p.probes[t]; !ok {
		return errfmt.Errorf("probe handle (%d) does not exist", t)
	}

	return p.probes[t].attach(p.module, args...)
}

func (p *probes) Detach(t TracePoint, args ...any) error {
	if _, ok := p.probes[t]; !ok {
		return errfmt.Errorf("probe handle (%d) does not exist", t)
	}

	return p.probes[t].detach(args...)
}

func (p *probes) DetachAll() error {
	for _, pr := range p.probes {
		err := pr.detach()
		if err != nil {
			return errfmt.WrapError(err)
		}
	}

	return nil
}
