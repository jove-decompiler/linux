// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <string.h>
#include <unistd.h>
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define MAX_PATH_LEN		128
#define MAX_EVENT_NUM		16

static struct fd_path_test_data {
	pid_t pid;
	__u32 cnt;
	__u32 fds[MAX_EVENT_NUM];
	char paths[MAX_EVENT_NUM][MAX_PATH_LEN];
} data;

struct sys_enter_newfstat_args {
	unsigned long long pad1;
	unsigned long long pad2;
	unsigned long fd;
};

SEC("tracepoint/syscalls/sys_enter_newfstat")
int bpf_prog(struct sys_enter_newfstat_args *args)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != data.pid)
		return 0;
	if (data.cnt >= MAX_EVENT_NUM)
		return 0;

	data.fds[data.cnt] = args->fd;
	bpf_get_fd_path(data.paths[data.cnt], MAX_PATH_LEN, args->fd);
	data.cnt++;

	return 0;
}

char _license[] SEC("license") = "GPL";
