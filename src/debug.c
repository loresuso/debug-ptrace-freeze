#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

#include "debug.skel.h"
#include "debug.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	enum type *t = (enum type *)data;

	switch (*t)
	{
	case PTRACE_ATTACH:
	{
		struct evt_ptrace_attach *e = (struct evt_ptrace_attach *)data;
		printf("%s: %d -> (comm: %s, pid: %d)\n",
			   type_to_str[*t],
			   e->pid,
			   e->ptraced_comm,
			   e->ptraced_tid);
		break;
	}
	case FREEZE_TASK:
	{
		struct evt_freeze_thaw_task *e = (struct evt_freeze_thaw_task *)data;
		printf("%s: %s -> (comm: %s, pid: %d)\n", type_to_str[*t], e->current, e->comm, e->tid);
		break;
	}
	case THAW_TASK:
	{
		struct evt_freeze_thaw_task *e = (struct evt_freeze_thaw_task *)data;
		printf("%s: %s -> (comm: %s, pid: %d)\n", type_to_str[*t], e->current, e->comm, e->tid);
		break;
	}
	case CGROUP_FREEZE_TASK:
	{
		struct evt_cgroup_freeze_task *e = (struct evt_cgroup_freeze_task *)data;
		printf("%s %s: (comm: %s, pid: %d)\n", 
			type_to_str[*t],
			e->freeze ? "[FREEZING]" : "[UNFREEZING]",
			e->comm,
			e->tid
		);
		break;
	}
	default:
		puts("unrecognized event type");
		break;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct debug_bpf *skel;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open load and verify BPF application */
	skel = debug_bpf__open_and_load();
	if (!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = debug_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR)
	{
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	puts("Successfully started!\n");

	while (!stop)
	{
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR)
		{
			err = 0;
			break;
		}

		if (err < 0)
		{
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	debug_bpf__destroy(skel);
	return -err;
}