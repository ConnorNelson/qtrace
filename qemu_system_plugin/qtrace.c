/*
 * QEMU-SYSTEM BASED TRACER
 * ------------------------
 * This plugin supports tracing a target process running within a full QEMU
 * system instance. To identify execution of the target process among other
 * processes running in the system, this plugin supports a simple virtual memory
 * matching test.
 *
 */

#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <poll.h>
#include <qemu-plugin.h>

#define DEBUG 1

#ifdef DEBUG
#define DPRINTF(...) do { fprintf(stderr, __VA_ARGS__); } while (0)
#else
#define DPRINTF(...) do { } while (0)
#endif

#define MAX(a,b) ((a)>(b)?(a):(b))

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#pragma pack(push, 1)

enum {
    MESSAGE_TYPE_START,
    MESSAGE_TYPE_TRACE,
};

typedef struct {
    uint16_t msg_type;
    uint16_t msg_len;
} Message;

typedef struct {
    uint64_t addr;
    uint16_t len;
    uint8_t  data[];
} CheckedRegion;

typedef struct {
    Message hdr;
    uint64_t entry_addr;
    uint16_t num_regions;
    /* CheckedRegion entries follow... */
} MessageStart;

typedef struct {
    Message hdr;
    uint64_t addr;
} MessageTrace;

#pragma pack(pop)

static CheckedRegion *mem_checks;
static size_t num_mem_checks;
static char *mem_check_buf;

static uint64_t entry_addr;
static bool reached_start;

static int server_fd;
static int client_fd = -1;

static void handle_start_msg(MessageStart *msg);

static
bool read_all(void *buf, size_t count)
{
    for (size_t bytes_read = 0; bytes_read < count;) {
        ssize_t l = read(client_fd, (char*)buf+bytes_read, count-bytes_read);
        if (l <= 0) return false;
        bytes_read += l;
    }
    return true;
}

static
Message *recv_msg(void)
{
    Message hdr;
    if (!read_all(&hdr, sizeof(hdr))) return NULL;
    if (hdr.msg_len < sizeof(hdr)) return NULL;

    Message *msg = malloc(hdr.msg_len);
    if (msg == NULL) return NULL;
    memcpy(msg, &hdr, sizeof(hdr));
    if (!read_all(msg+1, hdr.msg_len-sizeof(hdr))) {
        free(msg);
        return NULL;
    }
    return msg;
}

static
bool fd_pollin(int fd)
{
    int events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
    struct pollfd pfd = { .fd = fd, .events = events, .revents = 0 };
    return (poll(&pfd, 1, 0) > 0) && (pfd.revents & events);
}

static
void recv_msgs(void)
{
    if (client_fd < 0) {
        if (!fd_pollin(server_fd)) return; /* No connections pending */
        DPRINTF("New conn\n");
        client_fd = accept(server_fd, NULL, NULL);
    }

    if (!fd_pollin(client_fd)) return; /* No messages pending */

    Message *msg = recv_msg();
    if (msg == NULL) {
        DPRINTF("Disconnecting\n");
        close(client_fd);
        client_fd = -1;
        return;
    }
    if (msg->msg_type == MESSAGE_TYPE_START) {
        handle_start_msg((MessageStart*)msg);
    }
    free(msg);
}

static
bool write_all(const void *buf, size_t count)
{
    for (size_t bytes_written = 0; bytes_written < count;) {
        ssize_t l = write(client_fd, (char*)buf+bytes_written, count-bytes_written);
        if (l < 0) return false;
        bytes_written += l;
    }
    return true;
}

static
bool send_msg(Message *msg)
{
    if (!write_all(msg, msg->msg_len)) {
        DPRINTF("Send failed...Disconnecting\n");
        close(client_fd);
        client_fd = -1;
        return false;
    }
    return true;
}

static
void handle_start_msg(MessageStart *msg)
{
    size_t max_region_len = 0;

    /* Validate memory checks */
    char *end = (char*)msg + msg->hdr.msg_len;
    CheckedRegion *r = (CheckedRegion *)(msg+1);
    for (int i = 0; i < msg->num_regions; i++) {
        assert((char*)r < end);
        max_region_len = MAX(max_region_len, r->len);
        DPRINTF("Checked Region %d: %lx (%d bytes)\n", i, r->addr, r->len);

        /* Move to next region, make sure it doesn't put us outside the msg */
        r = (CheckedRegion *)((char *)r + sizeof(r) + r->len);
        assert((char*)r <= end);
    }

    /* Reallocate memory checks buffer and copy all checks over */
    size_t mem_checks_len = msg->hdr.msg_len - sizeof(MessageStart);
    mem_checks = realloc(mem_checks, mem_checks_len);
    assert(mem_checks != NULL);
    memcpy(mem_checks, msg+1, mem_checks_len);
    num_mem_checks = msg->num_regions;
    entry_addr = msg->entry_addr;

    mem_check_buf = realloc(mem_check_buf, max_region_len);

    reached_start = false;

    /* FIXME: Ideally this would flush the TLB */
}

static
bool send_trace_msg(uint64_t addr)
{
    if (client_fd < 0) return false;

    static MessageTrace msg = {
        .hdr = { .msg_type = MESSAGE_TYPE_TRACE, .msg_len = sizeof(MessageTrace) }
    };

    msg.addr = addr;
    return send_msg((Message*)&msg);
}

static
void begin_listening(void)
{
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        assert(0);
    }

    int tmp = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &tmp, sizeof(tmp));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(4242);
    if (bind(server_fd, (struct sockaddr *) &addr, sizeof(addr))) {
        perror("bind");
        assert(0);
    }

    if (listen(server_fd, 1)) {
        perror("listen");
        assert(0);
    }
}

/*
 * Determine if this particular callback (TB translate, exec) should execute
 * based on whether the target process is loaded or not.
 */
static
bool target_found_in_memory(void)
{
    CheckedRegion *c = mem_checks;
    for (size_t i = 0; i < num_mem_checks; i++) {
        if (!qemu_plugin_mem_read(0, c->addr, c->len, mem_check_buf))
            return false; /* Failed to read */
        if (memcmp(c->data, mem_check_buf, c->len))
            return false; /* Mismatch */

        c = (CheckedRegion *)((char *)c + sizeof(c) + c->len);
    }

    return true;
}

static
void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    recv_msgs();
    if ((num_mem_checks == 0) || !target_found_in_memory()) {
        return;
    }

    uint64_t addr = (uint64_t) udata;
    reached_start |= (addr == entry_addr);
    if (reached_start) {
        DPRINTF("exec(0x%lx)\n", addr);
        send_trace_msg(addr);
    }
}

static
void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    recv_msgs();
    if ((num_mem_checks == 0) || !target_found_in_memory()) {
        return;
    }

    uint64_t addr = qemu_plugin_tb_vaddr(tb);
    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec,
                                         QEMU_PLUGIN_CB_NO_REGS,
                                         (void *) addr);

}

#if 0
static
void vcpu_syscall(qemu_plugin_id_t id, unsigned int vcpu_index,
                  int64_t num, uint64_t a1, uint64_t a2,
                  uint64_t a3, uint64_t a4, uint64_t a5,
                  uint64_t a6, uint64_t a7, uint64_t a8)
{
    if (!should_instrument()) return;

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

    DPRINTF("syscall(%ld)\n");
}

static
void vcpu_syscall_ret(qemu_plugin_id_t id, unsigned int vcpu_index, int64_t num,
                      int64_t ret)
{
    if (!should_instrument()) return;

    struct trace_info info;
    info.syscall_num = num;
    info.syscall_ret = ret;
}
#endif

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);

#if 0
    qemu_plugin_register_vcpu_syscall_cb(id, vcpu_syscall);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, vcpu_syscall_ret);
#endif

    begin_listening();

    return 0;
}
