#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <semaphore.h>

#include <qemu-plugin.h>
#include "qtrace.h"


QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
struct trace trace;
sem_t trace_mutex;
sem_t ack_mutex;


static void unlocked_trace_flush(enum reason reason, struct trace_info info) {
    size_t size;

    trace.header.reason = reason;
    trace.header.info = info;

    size = sizeof(trace.header) + (trace.header.num_addrs * sizeof(uint64_t));
    assert(write(TRACE_FD, &trace, size) == size);
    sem_wait(&ack_mutex);

    trace.header.reason = 0;
    trace.header.num_addrs = 0;
    trace.header.info = EMPTY_INFO;
}

static void trace_flush(enum reason reason, struct trace_info info) {
    sem_wait(&trace_mutex);
    unlocked_trace_flush(reason, info);
    sem_post(&trace_mutex);
}

static void trace_add_bb_addr(uint64_t addr)
{
    sem_wait(&trace_mutex);
    trace.bb_addrs[trace.header.num_addrs++] = addr;
    if (trace.header.num_addrs == TRACE_MAX_BB_ADDRS)
        unlocked_trace_flush(trace_full, EMPTY_INFO);
    sem_post(&trace_mutex);
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

static void *async_trace_flush(void *arg)
{
    trace_flush(trace_async, EMPTY_INFO);
}

static void *handle_client(void *arg)
{
    uint64_t response;
    pthread_t flush_thread;

    while (true) {
        assert(read(TRACE_FD, &response, sizeof(response)) == sizeof(response));

        switch (response) {
        case RESPONSE_ACK:
            sem_post(&ack_mutex);
            break;
        case RESPONSE_FLUSH:
            pthread_create(&flush_thread, NULL, async_trace_flush, NULL);
            break;
        default:
            assert(false);
            break;
        }
    }
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    int server_fd;
    int client_fd;
    struct sockaddr_in server_addr;
    pthread_t client_thread;

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

    sem_init(&trace_mutex, 0, 1);
    sem_init(&ack_mutex, 0, 0);

    pthread_create(&client_thread, NULL, handle_client, NULL);

    return 0;
}
