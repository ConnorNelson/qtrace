#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <fcntl.h>
#include <signal.h>
#include <assert.h>
#include <sys/sendfile.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define TRACE_MAX_BB_ADDRS  0x1000
#define TRACE_FLUSH_FULL    -1
#define TRACE_PIPE_READ     254
#define TRACE_PIPE_WRITE    255

struct {
    uint64_t reason;
    uint64_t num_addrs;
    uint64_t bb_addrs[TRACE_MAX_BB_ADDRS];
} trace;

static inline void trace_flush(int64_t reason) {
    size_t size;
    uint64_t response;

    trace.reason = reason;

    size = sizeof(uint64_t) * (trace.num_addrs + 2);
    assert(write(TRACE_PIPE_WRITE, &trace, size) == size);
    assert(read(TRACE_PIPE_READ, &response, sizeof(response)) == sizeof(response));

    trace.num_addrs = 0;
}

static inline void trace_add_bb_addr(uint64_t addr)
{
    trace.bb_addrs[trace.num_addrs++] = addr;
    if (trace.num_addrs == TRACE_MAX_BB_ADDRS)
        trace_flush(-1);
}

static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    uint64_t addr = (uint64_t) udata;
    trace_add_bb_addr(addr);
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    uint64_t addr = qemu_plugin_tb_vaddr(tb);

    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         (void *) addr);
}

static void vcpu_syscall(qemu_plugin_id_t id, unsigned int vcpu_index,
                         int64_t num, uint64_t a1, uint64_t a2,
                         uint64_t a3, uint64_t a4, uint64_t a5,
                         uint64_t a6, uint64_t a7, uint64_t a8)
{
    //printf("SYSCALL: %"PRId64"\n", num);
    trace_flush(num);
}

static void vcpu_syscall_ret(qemu_plugin_id_t id, unsigned int vcpu_index,
                             int64_t num, int64_t ret)
{
    //printf("SYSCALL: %"PRId64" = %"PRId64"\n", num, ret);
    trace_flush(num);
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    int fd;
    char *trace_pipe_read_path;
    char *trace_pipe_write_path;
    uint64_t data = 0;

    assert(argc == 2);
    trace_pipe_read_path = argv[0];
    trace_pipe_write_path = argv[1];

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    assert((fd = open(trace_pipe_write_path, O_WRONLY)) != -1);
    assert(dup2(fd, TRACE_PIPE_WRITE) != -1);
    assert(close(fd) != -1);
    write(TRACE_PIPE_WRITE, &data, sizeof(data));

    assert((fd = open(trace_pipe_read_path, O_RDONLY)) != -1);
    assert(dup2(fd, TRACE_PIPE_READ) != -1);
    assert(close(fd) != -1);
    read(TRACE_PIPE_READ, &data, sizeof(data));

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_vcpu_syscall_cb(id, vcpu_syscall);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, vcpu_syscall_ret);

    return 0;
}
