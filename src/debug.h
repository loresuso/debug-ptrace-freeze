#pragma once

#define TASK_COMM 16

enum type
{
	PTRACE_ATTACH,
	FREEZE_TASK,
	THAW_TASK,
	CGROUP_FREEZE_TASK,
};

const char *type_to_str[] = {
    [PTRACE_ATTACH] = "ptrace_attach",
    [FREEZE_TASK] = "freeze_task",
    [THAW_TASK] = "thaw_task",
	[CGROUP_FREEZE_TASK] = "cgroup_freeze_task",
};

struct evt_ptrace_attach
{
	enum type t;
	int pid;
	char ptraced_comm[TASK_COMM];
	int ptraced_tid;
};

struct evt_freeze_thaw_task
{
	enum type t;
	char current[TASK_COMM];
	char comm[TASK_COMM];
	int tid;
};

struct evt_cgroup_freeze_task
{
	enum type t;
	bool freeze;
	char comm[TASK_COMM];
	int tid;
};