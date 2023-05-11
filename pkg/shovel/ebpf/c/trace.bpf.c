// +build ignore

#include <vmlinux.h>
#include <vmlinux_flavors.h>
#include <vmlinux_missing.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <maps.h>
#include <types.h>


#include <common/arch.h>
#include <common/arguments.h>
#include <common/binprm.h>
#include <common/bpf_prog.h>
#include <common/buffer.h>
#include <common/capabilities.h>
#include <common/cgroups.h>
#include <common/common.h>
#include <common/consts.h>
#include <common/context.h>
#include <common/filesystem.h>
#include <common/filtering.h>
#include <common/kconfig.h>
#include <common/ksymbols.h>
#include <common/logging.h>
#include <common/memory.h>
#include <common/network.h>
#include <common/probes.h>

char LICENSE[] SEC("license") = "GPL";


// SYSCALL HOOKS -----------------------------------------------------------------------------------

// trace/events/syscalls.h: TP_PROTO(struct pt_regs *regs, long id)
// initial entry for sys_enter syscall logic
SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    int id = ctx -> args[1];
    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &id);
        if (id_64 == 0)
            return 0;

        id = *id_64;
    }
    bpf_tail_call(ctx, &sys_enter_init_tail, id);
    return 0;
}

// tracepoint_demo
SEC("kprobe/sys_mmap")
int kprobe__sys_mmap(struct pt_regs *ctx)
{
    bpf_printk("Yankees will win the 2022 world series");
    return 0;
}
