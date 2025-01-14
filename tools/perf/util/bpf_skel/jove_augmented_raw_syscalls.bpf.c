#include "vmlinux.h"
#include <linux/limits.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/repetition/repeat.hpp>
typedef u8 uint8_t;
typedef signed char int8_t;
typedef u32 uint32_t;
typedef s32 int32_t;
typedef u64 uint64_t;
typedef s64 int64_t;
#include "augmented_raw_syscalls.h"

#if defined(IFDEBUG) || defined(NOP)
#error
#endif

#define NDEBUG

#ifdef NDEBUG
#define IFDEBUG 0
#else
#define IFDEBUG 1
#endif
#define NOP() do {} while (false)

#define VERY_UNIQUE_BASE 0xfffffff
#define VERY_UNIQUE_NUM() (VERY_UNIQUE_BASE + __COUNTER__)

#define ___SYSCALL(nr, nm) \
  static const unsigned nr64_##nm = nr;\
  static const char *const nr64_##nm##_nm = #nm;

#include <arch/x86_64/syscalls.inc.h>
static const unsigned nr64_clone3 = VERY_UNIQUE_NUM();
static const unsigned nr64_mmap_pgoff = VERY_UNIQUE_NUM();

#define ___SYSCALL(nr, nm) static const unsigned nr32_##nm = nr;\
  static const char *const nr32_##nm##_nm = #nm;
#include <arch/i386/syscalls.inc.h>
static const unsigned nr32_mmap = VERY_UNIQUE_NUM();

#ifndef TS_COMPAT
#define TS_COMPAT		0x0002	/* 32bit syscall active (64BIT)*/
#endif

#define MAX_ARG_COUNT 10
#define MAX_ENV_COUNT 60

#define MAX_BPF_PRINK_LEN 128

static bool bpf_in_ia32_syscall(void) {
  u32 status;
  bpf_probe_read_kernel(&status, sizeof(status),
                        (void *)bpf_get_current_task() +
                            2 * sizeof(long unsigned int));

  return !!(status & TS_COMPAT);
}

struct syscall_enter_args {
  unsigned long long common_tp_fields;
  long syscall_nr;
  unsigned long args[6];
};

struct syscall_exit_args {
  unsigned long long common_tp_fields;
  long syscall_nr;
  long ret;
};

union augmented_syscall_payload_u {
  struct augmented_syscall_payload32 _32;
  struct augmented_syscall_payload64 _64;
};

struct augmented_syscalls_tmp {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, int);
  __type(value, union augmented_syscall_payload_u);
  __uint(max_entries, 1);
} augmented_syscalls_tmp SEC(".maps");

struct __jove_augmented_syscalls__ {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __type(key, int);
  __type(value, int);
} __jove_augmented_syscalls__ SEC(".maps");

struct pids_filtered {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, pid_t);
  __type(value, bool);
  __uint(max_entries, 64);
} pids_unfiltered SEC(".maps");

unsigned dev = 0;
unsigned ino = 0;

static pid_t our_pid(void) {
  struct bpf_pidns_info nsdata;

  if (bpf_get_ns_current_pid_tgid(dev, ino, &nsdata, sizeof(nsdata)))
    return ~0u;

  return nsdata.tgid;
}

static bool check_pid(pid_t pid) {
  return bpf_map_lookup_elem(&pids_unfiltered, &pid) != NULL;
}

static union augmented_syscall_payload_u *augmented_syscall_payload(void) {
  int key = 0;
  union augmented_syscall_payload_u *res =
	  bpf_map_lookup_elem(&augmented_syscalls_tmp, &key);

  if (res == NULL)
    bpf_printk("augmented_syscall_payload failed!!!\n");

  return res;
}

#define DO_READ_STRING(str_arg, what_done)                                     \
  do {                                                                         \
    void *const c_str = (void *)str_arg;                                       \
    if (c_str) {                                                               \
      long path_len = bpf_probe_read_user_str(                                 \
          &payload->str[pos & HALFMAXMASK], HALFMAXLEN, c_str);                \
      if (path_len >= 1) {                                                     \
        pos += path_len;                                                       \
      } else {                                                                 \
        payload->str[pos & HALFMAXMASK] = '\0'; /* error */                    \
        ++pos;                                                                 \
      }                                                                        \
      if (pos >= HALFMAXLEN)                                                   \
        goto what_done##_done; /* overflow */                                  \
    } else {                                                                   \
      goto what_done##_done;                                                   \
    }                                                                          \
  } while (false);

#define CLEAR_STUFF(count)                       \
  do {                                           \
    BOOST_PP_REPEAT(count, DO_CLEAR_STUFF, void) \
  } while (false)

#define DO_CLEAR_STUFF(n, i, data) the_stuff[i] = 0;

#define READ_STUFF(count, what) \
  do {                          \
    CLEAR_STUFF(count);         \
    DO_READ_STUFF(what);        \
  } while (false)

#define DO_READ_STUFF(what)                                                    \
  do {                                                                         \
    if (bpf_probe_read_user(the_stuff, sizeof(the_stuff), (void *)what) < 0)   \
      return 0;                                                                \
  } while (false)

#define READ_ARGV_STUFF() READ_STUFF(MAX_ARG_COUNT, argv)
#define READ_ENVP_STUFF() READ_STUFF(MAX_ENV_COUNT, envp)

#define DO_READ_ARG(n, i, data) DO_READ_STRING(the_stuff[i], args)
#define DO_READ_ENV(n, i, data) DO_READ_STRING(the_stuff[i], envs)

#define READ_ARGV() BOOST_PP_REPEAT(MAX_ARG_COUNT, DO_READ_ARG, void)
#define READ_ENVP() BOOST_PP_REPEAT(MAX_ENV_COUNT, DO_READ_ENV, void)

#define ON_ENTER_EXEC(bits)                                                    \
  static int on_enter_exec##bits(                                              \
      struct augmented_syscall_payload##bits *payload, u##bits pathname,       \
      u##bits argv, u##bits envp) {                                            \
    volatile /* !!! */ unsigned pos = 0;                                       \
    DO_READ_STRING(pathname, path);                                            \
  path_done:                                                                   \
    if (argv) {                                                                \
      u##bits the_stuff[MAX_ARG_COUNT];                                        \
      READ_ARGV_STUFF();                                                       \
      READ_ARGV();                                                             \
    }                                                                          \
  args_done:                                                                   \
    payload->str[pos & HALFMAXMASK] = '\0';                                    \
    ++pos;                                                                     \
    if (envp) {                                                                \
      u##bits the_stuff[MAX_ENV_COUNT];                                        \
      READ_ENVP_STUFF();                                                       \
      READ_ENVP();                                                             \
    }                                                                          \
  envs_done:                                                                   \
    payload->hdr.str_len = pos;                                                \
                                                                               \
    return 0;                                                                  \
  }

ON_ENTER_EXEC(32)
ON_ENTER_EXEC(64)

#define ON_SYS_ENTER_EXECVE(bits)                                              \
  static int on_sys_enter_execve##bits(                                        \
      struct augmented_syscall_payload##bits *payload,                         \
      struct syscall_enter_args *args) {                                       \
    return on_enter_exec##bits(payload, args->args[0], args->args[1],          \
                               args->args[2]);                                 \
  }

ON_SYS_ENTER_EXECVE(32)
ON_SYS_ENTER_EXECVE(64)

#define ON_SYS_ENTER_EXECVEAT(bits)                                            \
  static int on_sys_enter_execveat##bits(                                      \
      struct augmented_syscall_payload##bits *payload,                         \
      struct syscall_enter_args *args) {                                       \
    return on_enter_exec##bits(payload, args->args[1], args->args[2],          \
                               args->args[3]);                                 \
  }

ON_SYS_ENTER_EXECVEAT(32)
ON_SYS_ENTER_EXECVEAT(64)

#define SET_MAGIC0() NOP()
#define SET_MAGIC1()                      \
  do {                                    \
    if (MAGIC_LEN == 4) {                 \
      payload->hdr.magic1[0] = 'J';       \
      payload->hdr.magic1[1] = 'O';       \
      payload->hdr.magic1[2] = 'V';       \
      payload->hdr.magic1[3] = 'E';       \
                                          \
      payload->hdr.magic2[0] = 'E';       \
      payload->hdr.magic2[1] = 'V';       \
      payload->hdr.magic2[2] = 'O';       \
      payload->hdr.magic2[3] = 'J';       \
    }                                     \
  } while (false)

SEC("tp/raw_syscalls/sys_enter")
int sys_enter(struct syscall_enter_args *args)
{
#if 0
  if (!check_pid())
    return 0;
#endif

  //bpf_printk("sys_enter: %u\n", (unsigned)our_pid());

  union augmented_syscall_payload_u *payload_u = augmented_syscall_payload();
  if (payload_u == NULL)
    return 0;

  const bool is32 = bpf_in_ia32_syscall();
  const long nr = args->syscall_nr;

#define ON_SYS_ENTER(bits)                                                     \
  do {                                                                         \
    struct augmented_syscall_payload##bits *payload = &payload_u->_##bits;     \
                                                                               \
    BOOST_PP_CAT(SET_MAGIC,IFDEBUG)();                                         \
                                                                               \
    payload->str[0] = '\0';                                                    \
    payload->hdr.str_len = 0;                                                  \
    payload->hdr.was32 = is32;                                                 \
    payload->hdr.syscall_nr = nr;                                              \
    payload->hdr.ret = -1;                                                     \
                                                                               \
    switch (nr) {                                                              \
    case nr##bits##_execve:                                                    \
      payload->hdr.ret = 1;                                                     \
      bpf_perf_event_output(                                                   \
             args, &__jove_augmented_syscalls__, BPF_F_CURRENT_CPU, &payload->hdr, \
             sizeof(payload->hdr));                                            \
      payload->hdr.ret = -1;                                                   \
      on_sys_enter_execve##bits(payload, args);                                \
      break;                                                                   \
    case nr##bits##_execveat:                                                  \
      payload->hdr.ret = 1;                                                     \
      bpf_perf_event_output(                                                   \
             args, &__jove_augmented_syscalls__, BPF_F_CURRENT_CPU, &payload->hdr, \
             sizeof(payload->hdr));                                            \
      payload->hdr.ret = -1;                                                   \
      on_sys_enter_execveat##bits(payload, args);                              \
      break;                                                                   \
    case nr##bits##_mmap:                                                      \
    case nr##bits##_mmap_pgoff:                                                \
      break;                                                                   \
    case nr##bits##_close:                                                     \
    case nr##bits##_munmap:                                                    \
    case nr##bits##_read:                                                      \
    case nr##bits##_pread64:                                                   \
    case nr##bits##_open:                                                      \
    case nr##bits##_openat:                                                    \
      break;                                                                   \
    default:                                                                   \
      return 0;                                                                \
    }                                                                          \
                                                                               \
    payload->hdr.args[0] = args->args[0];                                      \
    payload->hdr.args[1] = args->args[1];                                      \
    payload->hdr.args[2] = args->args[2];                                      \
    payload->hdr.args[3] = args->args[3];                                      \
    payload->hdr.args[4] = args->args[4];                                      \
    payload->hdr.args[5] = args->args[5];                                      \
  } while (false)

  if (is32)
    ON_SYS_ENTER(32);
  else
    ON_SYS_ENTER(64);

#undef ON_SYS_ENTER

  return 0;
}

SEC("tp/raw_syscalls/sys_exit")
int sys_exit(struct syscall_exit_args *args)
{
  pid_t ourpid = our_pid();
  if (!check_pid(ourpid))
    return 0;

  union augmented_syscall_payload_u *payload_u = augmented_syscall_payload();
  if (payload_u == NULL)
    return 0;

  const bool was32 = !!(((const uint8_t *)payload_u)[MAGIC_LEN] & 1u);
  const bool is32 = bpf_in_ia32_syscall();
  const bool diff32 = is32 != was32;
  const unsigned nr = args->syscall_nr;

#define CASE(bits, nm)                                         \
  case BOOST_PP_CAT(BOOST_PP_CAT(BOOST_PP_CAT(nr,bits),_),nm): \
    if (!sysnm){sysnm=#nm;}                                    \
    BOOST_PP_CAT(BOOST_PP_CAT(label_for_,nm),__COUNTER__)

#define ON_SYS_EXIT(bits)                                                      \
  do {                                                                         \
    const uint##bits##_t uret = args->ret;                                     \
    const int##bits##_t ret = (int##bits##_t)uret;                             \
                                                                               \
    struct augmented_syscall_payload##bits *payload = &payload_u->_##bits;     \
                                                                               \
    const long wasnr = payload->hdr.syscall_nr;                                \
    __attribute__((maybe_unused)) const char *sysnm = NULL;\
                                                                               \
    bool uhoh = diff32;                                                        \
                                                                               \
    switch (wasnr) {                                                           \
    CASE(bits,clone):                                                          \
    CASE(bits,clone3):                                                         \
    CASE(bits,fork): {                                                         \
      if (ret <= 0)                                                            \
        return 0;                                                              \
                                                                               \
      /* XXX is this racy? */                                                  \
      pid_t key = ret;                                                         \
      bool value = true;                                                       \
      bpf_map_update_elem(&pids_unfiltered, &key, &value, BPF_ANY);            \
      return 0;                                                                \
    }                                                                          \
    CASE(bits,execve):                                                         \
    CASE(bits,execveat):                                                       \
      if (diff32) {                                                            \
        if (bits == 32) {                                                      \
          uhoh = !((wasnr == nr32_execve && nr == nr64_execve) ||              \
                   (wasnr == nr32_execveat && nr == nr64_execve));             \
        } else {                                                               \
          uhoh = !((wasnr == nr64_execve && nr == nr32_execve) ||              \
                   (wasnr == nr64_execveat && nr == nr32_execve));             \
        }                                                                      \
      }                                                                        \
      break;                                                                   \
                                                                               \
    CASE(bits,mmap):                                                           \
    CASE(bits,mmap_pgoff):                                                     \
      if (uret >= (uint##bits##_t)-4095)                                       \
        return 0; /* failed */                                                 \
      break;                                                                   \
                                                                               \
    CASE(bits,close):                                                          \
    CASE(bits,munmap):                                                         \
      if (ret != 0)                                                            \
        return 0;                                                              \
      break;                                                                   \
                                                                               \
    CASE(bits,read):                                                           \
    CASE(bits,pread64):                                                        \
      if (ret <= 0) \
        return 0; \
      break;                                                                   \
                                                                               \
    CASE(bits,open): {                                                         \
      if (ret < 0)                                                             \
        return 0;                                                              \
      long rdret = bpf_probe_read_user_str(payload->str, MAXLEN, (void *)payload->hdr.args[0]);    \
      if (rdret >= 1) {\
        payload->hdr.str_len = rdret;\
      } else {\
        return 0;\
      }\
      break;                                                                   \
    }                                                                          \
    CASE(bits,openat): {                                                       \
      if (ret < 0)                                                             \
        return 0;                                                              \
      long rdret = bpf_probe_read_user_str(payload->str, MAXLEN, (void *)payload->hdr.args[1]);    \
      if (rdret >= 1) {\
        payload->hdr.str_len = rdret;\
      } else {\
        return 0;\
      }\
      break;                                                                   \
    }\
    default:                                                                   \
      return 0;                                                                \
    }                                                                          \
                                                                               \
    payload->hdr.ret = ret;                                                    \
    payload->hdr.is32 = is32;                                                  \
                                                                               \
    BOOST_PP_CAT(PRINT_PAYLOAD,IFDEBUG)();                                     \
    OUTPUT_PAYLOAD(bits);                                                      \
                                                                               \
    payload->hdr.syscall_nr = ~0u;                                             \
  } while (false)

#define FMT_STR1 "%s on %ld (%ld) \"%s\" <%u>\n"
#define FMT_ARGS1 sysnm, nr, wasnr, payload->str,  ourpid

#define FMT_STR2 "%s on %ld (%ld) <%u>\n"
#define FMT_ARGS2 sysnm, nr, wasnr, ourpid

#define DO_PRINT_PAYLOAD(msg) do {                                             \
    if (payload->hdr.str_len > 0)                                              \
      bpf_printk(msg " " FMT_STR1, FMT_ARGS1);                                 \
    else                                                                       \
      bpf_printk(msg " " FMT_STR2, FMT_ARGS2);                                 \
  } while(false)

#define PRINT_PAYLOAD0() NOP()
#define PRINT_PAYLOAD1()                                                       \
  do {                                                                         \
    char sav;                                                                  \
    const bool has_str = payload->hdr.str_len > 0;                             \
    if (has_str) {                                                             \
      sav = payload->str[MAX_BPF_PRINK_LEN];                                   \
      payload->str[MAX_BPF_PRINK_LEN] = '\0';                                  \
    }                                                                          \
    if (uhoh) {                                                                \
      if (is32)                                                                \
        DO_PRINT_PAYLOAD("uhhh oh! [32]");                                     \
      else                                                                     \
        DO_PRINT_PAYLOAD("uhhh oh! [64]");                                     \
    } else {                                                                   \
      if (is32) {                                                              \
        if (diff32)                                                            \
          DO_PRINT_PAYLOAD("[64 -> 32]");                                      \
        else                                                                   \
          DO_PRINT_PAYLOAD("[32]");                                            \
      } else {                                                                 \
        if (diff32)                                                            \
          DO_PRINT_PAYLOAD("[32 -> 64]");                                      \
        else                                                                   \
          DO_PRINT_PAYLOAD("[64]");                                            \
      }                                                                        \
    }                                                                          \
    if (has_str) {                                                             \
      payload->str[MAX_BPF_PRINK_LEN] = sav;                                   \
    }                                                                          \
  } while (false)

#define OUTPUT_PAYLOAD(bits)                                                   \
  do {                                                                         \
    unsigned the_payload_size =                                                \
        sizeof(struct augmented_syscall_payload##bits##_header) +              \
        payload->hdr.str_len;                                                  \
                                                                               \
    long err;                                                                  \
    if ((err = bpf_perf_event_output(                                          \
             args, &__jove_augmented_syscalls__, BPF_F_CURRENT_CPU, payload,   \
             the_payload_size & TWOTIMESMAXMASK)) < 0) {                       \
/*    bpf_printk("bpf_perf_event_output() failed! %ld", err);                */\
    } else {                                                                   \
/*    bpf_printk("bpf_perf_event_output() suceeded! (wrote %u)",             */\
/*               the_payload_size);                                          */\
    }                                                                          \
                                                                               \
    payload->hdr.ret = -1;                                                     \
    payload->hdr.str_len = 0;                                                  \
  } while (false)

  if (was32)
    ON_SYS_EXIT(32);
  else
    ON_SYS_EXIT(64);

#undef ON_SYS_EXIT
#undef FMT_ARGS
#undef FMT_STR

  return 0;
}

char _license[] SEC("license") = "GPL";
