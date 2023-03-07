#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "printk.bpf.h"

#define TASK_COMM 16

SEC("kprobe/ptrace_attach")
int BPF_KPROBE(ptrace_attach,
			   struct task_struct *task,
			   long request,
			   unsigned long addr,
			   unsigned long flags)
{
	char current_comm[TASK_COMM];
	pid_t pid;
	long ret;

	ret = bpf_get_current_comm(current_comm, TASK_COMM);
	if (ret)
	{
		bpf_printk("can't get current comm");
		return 0;
	}

	bpf_core_read(&pid, sizeof(pid_t), &task->pid);
	bpf_printk("ptrace_attach: (comm: %s) -> (comm: %s, pid: %d)",
			   current_comm,
			   task->comm,
			   pid);

	return 0;
}

/*
	Hook points for cgroup v1
*/
SEC("kprobe/freeze_task")
int BPF_KPROBE(freeze_task,
			   struct task_struct *task)
{
	pid_t pid;

	bpf_core_read(&pid, sizeof(pid_t), &task->pid);
	bpf_printk("freeze_task: (comm: %s, pid: %d)", task->comm, pid);

	return 0;
}

SEC("kprobe/__thaw_task")
int BPF_KPROBE(__thaw_task,
			   struct task_struct *task)
{
	pid_t pid;

	bpf_core_read(&pid, sizeof(pid_t), &task->pid);
	bpf_printk("__thaw_task: (comm: %s, pid: %d)", task->comm, pid);

	return 0;
}

/*
	Hook point for cgroup v2
*/
SEC("kprobe/cgroup_freeze_task")
int BPF_KPROBE(cgroup_freeze_task,
			   struct task_struct *task, bool freeze)
{
	pid_t pid;

	bpf_core_read(&pid, sizeof(pid_t), &task->pid);
	if (freeze)
		bpf_printk("cgroup_freeze_task [FREEZING]: (comm: %s, pid: %d)", task->comm, pid);
	else 
		bpf_printk("cgroup_freeze_task [UNFREEZING]: (comm: %s, pid: %d)", task->comm, pid);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";