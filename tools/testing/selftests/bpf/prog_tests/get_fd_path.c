// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <test_progs.h>
#include <sys/stat.h>
#include <linux/sched.h>
#include <sys/syscall.h>

#define MAX_PATH_LEN		128
#define MAX_FDS			7
#define MAX_EVENT_NUM		16

static struct fd_path_test_data {
	pid_t pid;
	__u32 cnt;
	__u32 fds[MAX_EVENT_NUM];
	char paths[MAX_EVENT_NUM][MAX_PATH_LEN];
} src, dst;

static int set_pathname(int fd)
{
	char buf[MAX_PATH_LEN];

	snprintf(buf, MAX_PATH_LEN, "/proc/%d/fd/%d", src.pid, fd);
	src.fds[src.cnt] = fd;
	return readlink(buf, src.paths[src.cnt++], MAX_PATH_LEN);
}

static int trigger_fstat_events(pid_t pid)
{
	int pipefd[2] = { -1, -1 };
	int sockfd = -1, procfd = -1, devfd = -1;
	int localfd = -1, indicatorfd = -1;
	struct stat fileStat;
	int ret = -1;

	/* unmountable pseudo-filesystems */
	if (CHECK_FAIL(pipe(pipefd) < 0))
		return ret;
	/* unmountable pseudo-filesystems */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (CHECK_FAIL(sockfd < 0))
		goto out_close;
	/* mountable pseudo-filesystems */
	procfd = open("/proc/self/comm", O_RDONLY);
	if (CHECK_FAIL(procfd < 0))
		goto out_close;
	devfd = open("/dev/urandom", O_RDONLY);
	if (CHECK_FAIL(devfd < 0))
		goto out_close;
	localfd = open("/tmp/fd2path_loadgen.txt", O_CREAT | O_RDONLY);
	if (CHECK_FAIL(localfd < 0))
		goto out_close;
	/* bpf_get_fd_path will return path with (deleted) */
	remove("/tmp/fd2path_loadgen.txt");
	indicatorfd = open("/tmp/", O_PATH);
	if (CHECK_FAIL(indicatorfd < 0))
		goto out_close;

	src.pid = pid;

	ret = set_pathname(pipefd[0]);
	if (CHECK_FAIL(ret < 0))
		goto out_close;
	ret = set_pathname(pipefd[1]);
	if (CHECK_FAIL(ret < 0))
		goto out_close;
	ret = set_pathname(sockfd);
	if (CHECK_FAIL(ret < 0))
		goto out_close;
	ret = set_pathname(procfd);
	if (CHECK_FAIL(ret < 0))
		goto out_close;
	ret = set_pathname(devfd);
	if (CHECK_FAIL(ret < 0))
		goto out_close;
	ret = set_pathname(localfd);
	if (CHECK_FAIL(ret < 0))
		goto out_close;
	ret = set_pathname(indicatorfd);
	if (CHECK_FAIL(ret < 0))
		goto out_close;

	fstat(pipefd[0], &fileStat);
	fstat(pipefd[1], &fileStat);
	fstat(sockfd, &fileStat);
	fstat(procfd, &fileStat);
	fstat(devfd, &fileStat);
	fstat(localfd, &fileStat);
	fstat(indicatorfd, &fileStat);

out_close:
	close(indicatorfd);
	close(localfd);
	close(devfd);
	close(procfd);
	close(sockfd);
	close(pipefd[1]);
	close(pipefd[0]);

	return ret;
}

void test_get_fd_path(void)
{
	const char *prog_name = "tracepoint/syscalls/sys_enter_newfstat";
	const char *obj_file = "test_get_fd_path.o";
	int err, results_map_fd, duration = 0;
	struct bpf_program *tp_prog = NULL;
	struct bpf_link *tp_link = NULL;
	struct bpf_object *obj = NULL;
	const int zero = 0;

	obj = bpf_object__open_file(obj_file, NULL);
	if (CHECK(IS_ERR(obj), "obj_open_file", "err %ld\n", PTR_ERR(obj)))
		return;

	tp_prog = bpf_object__find_program_by_title(obj, prog_name);
	if (CHECK(!tp_prog, "find_tp",
		  "prog '%s' not found\n", prog_name))
		goto cleanup;

	err = bpf_object__load(obj);
	if (CHECK(err, "obj_load", "err %d\n", err))
		goto cleanup;

	results_map_fd = bpf_find_map(__func__, obj, "test_get.bss");
	if (CHECK(results_map_fd < 0, "find_bss_map",
		  "err %d\n", results_map_fd))
		goto cleanup;

	tp_link = bpf_program__attach_tracepoint(tp_prog, "syscalls",
						 "sys_enter_newfstat");
	if (CHECK(IS_ERR(tp_link), "attach_tp",
		  "err %ld\n", PTR_ERR(tp_link))) {
		tp_link = NULL;
		goto cleanup;
	}

	dst.pid = getpid();
	err = bpf_map_update_elem(results_map_fd, &zero, &dst, 0);
	if (CHECK(err, "update_elem",
		  "failed to set pid filter: %d\n", err))
		goto cleanup;

	err = trigger_fstat_events(dst.pid);
	if (CHECK_FAIL(err < 0))
		goto cleanup;

	err = bpf_map_lookup_elem(results_map_fd, &zero, &dst);
	if (CHECK(err, "get_results",
		  "failed to get results: %d\n", err))
		goto cleanup;

	for (int i = 0; i < MAX_FDS; i++) {
		if (i < 3)
			CHECK((dst.paths[i][0] != 0), "get_fd_path",
			      "failed to filter fs [%d]: %u(%s) vs %u(%s)\n",
			      i, src.fds[i], src.paths[i], dst.fds[i],
			      dst.paths[i]);
		else
			CHECK(strncmp(src.paths[i], dst.paths[i], MAX_PATH_LEN),
			      "get_fd_path",
			      "failed to get path[%d]: %u(%s) vs %u(%s)\n",
			      i, src.fds[i], src.paths[i], dst.fds[i],
			      dst.paths[i]);
	}

cleanup:
	bpf_link__destroy(tp_link);
	bpf_object__close(obj);
}
