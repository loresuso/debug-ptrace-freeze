#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "printk.bpf.h"
#include "debug.h"

struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("kprobe/ptrace_attach")
int BPF_KPROBE(ptrace_attach,
			   struct task_struct *task,
			   long request,
			   unsigned long addr,
			   unsigned long flags)
{
	struct evt_ptrace_attach *e;
	int pid;
	long ret;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
	{
		bpf_printk("can't reserve space in ring buffer");
		return 0;
	}

	e->t = PTRACE_ATTACH;

	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_core_read(&e->ptraced_tid, sizeof(pid_t), &task->pid);
	bpf_core_read_str(&e->ptraced_comm, TASK_COMM, &task->comm);

	bpf_ringbuf_submit(e, 0);

	return 0;
}

/*
	Hook points for cgroup v1
*/
SEC("kprobe/freeze_task")
int BPF_KPROBE(freeze_task,
			   struct task_struct *task)
{
	struct evt_freeze_thaw_task *e;
	long ret;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
	{
		bpf_printk("can't reserve space in ring buffer");
		return 0;
	}

	e->t = FREEZE_TASK;

	bpf_get_current_comm(&e->current, TASK_COMM);
	bpf_core_read(&e->tid, sizeof(pid_t), &task->pid);
	bpf_core_read_str(&e->comm, TASK_COMM, &task->comm);

	bpf_ringbuf_submit(e, 0);

	// bpf_printk("freeze_task: (comm: %s, pid: %d)", task->comm, pid);

	return 0;
}

SEC("kprobe/__thaw_task")
int BPF_KPROBE(__thaw_task,
			   struct task_struct *task)
{
	struct evt_freeze_thaw_task *e;
	long ret;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
	{
		bpf_printk("can't reserve space in ring buffer");
		return 0;
	}

	e->t = THAW_TASK;

	bpf_get_current_comm(&e->current, TASK_COMM);
	bpf_core_read(&e->tid, sizeof(pid_t), &task->pid);
	bpf_core_read_str(&e->comm, TASK_COMM, &task->comm);

	bpf_ringbuf_submit(e, 0);

	return 0;
}

/*
	Hook point for cgroup v2
*/
SEC("kprobe/cgroup_freeze_task")
int BPF_KPROBE(cgroup_freeze_task,
			   struct task_struct *task, bool freeze)
{
	struct evt_cgroup_freeze_task *e;
	long ret;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
	{
		bpf_printk("can't reserve space in ring buffer");
		return 0;
	}

	e->t = CGROUP_FREEZE_TASK;

	bpf_core_read(&e->tid, sizeof(pid_t), &task->pid);
	e->freeze = freeze;
	bpf_core_read_str(&e->comm, TASK_COMM, &task->comm);

	bpf_ringbuf_submit(e, 0);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";