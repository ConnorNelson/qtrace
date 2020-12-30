#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <qemu-plugin.h>

#define TRACE_MAX_BB_ADDRS  0x1000
#define TRACE_FD            255

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

enum reason {
    trace_full = 0,
    trace_syscall_start = 1,
    trace_syscall_end = 2,
};

struct trace_info {
    int64_t syscall_num;
    union {
        struct {
            uint64_t syscall_a1;
            uint64_t syscall_a2;
            uint64_t syscall_a3;
            uint64_t syscall_a4;
            uint64_t syscall_a5;
            uint64_t syscall_a6;
            uint64_t syscall_a7;
            uint64_t syscall_a8;
        };
        int64_t syscall_ret;
    };
};
#define EMPTY_INFO (const struct trace_info) { 0 }

struct {
    struct {
        enum reason reason;
        uint64_t num_addrs;
        struct trace_info info;
    } header;
    uint64_t bb_addrs[TRACE_MAX_BB_ADDRS];
} trace;

static inline void trace_flush(enum reason reason, struct trace_info info) {
    size_t size;
    uint64_t response;

    trace.header.reason = reason;
    trace.header.info = info;

    size = sizeof(trace.header) + (trace.header.num_addrs * sizeof(uint64_t));
    assert(write(TRACE_FD, &trace, size) == size);
    assert(read(TRACE_FD, &response, sizeof(response)) == sizeof(response));

    trace.header.reason = 0;
    trace.header.num_addrs = 0;
    trace.header.info = EMPTY_INFO;
}

static inline void trace_add_bb_addr(uint64_t addr)
{
    trace.bb_addrs[trace.header.num_addrs++] = addr;
    if (trace.header.num_addrs == TRACE_MAX_BB_ADDRS)
        trace_flush(trace_full, EMPTY_INFO);
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
    struct trace_info info;
    info.syscall_num = num;
    info.syscall_a1 = a1;
    info.syscall_a2 = a2;
    info.syscall_a3 = a3;
    info.syscall_a4 = a4;
    info.syscall_a5 = a5;
    info.syscall_a6 = a6;
    info.syscall_a7 = a7;
    info.syscall_a8 = a8;

    trace_flush(trace_syscall_start, info);
}

static void vcpu_syscall_ret(qemu_plugin_id_t id, unsigned int vcpu_index,
                             int64_t num, int64_t ret)
{
    struct trace_info info;
    info.syscall_num = num;
    info.syscall_ret = ret;

    trace_flush(trace_syscall_end, info);
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    int server_fd;
    int client_fd;
    struct sockaddr_in server_addr;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &(int){1}, sizeof(int));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(4242);
    bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr));
    listen(server_fd, 1);
    client_fd = accept(server_fd, NULL, NULL);

    assert(dup2(client_fd, TRACE_FD) != -1);
    assert(close(client_fd) != -1);
    assert(close(server_fd) != -1);

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_vcpu_syscall_cb(id, vcpu_syscall);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, vcpu_syscall_ret);

    return 0;
}
