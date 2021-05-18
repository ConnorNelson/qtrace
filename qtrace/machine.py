import os
import fcntl
import select
import termios
import array
import enum
import ctypes
import threading
import subprocess
import pathlib

from . import (
    create_connection,
    syscalls,
    syscall_description,
    gdb_minimal_client,
    LD_PATH,
    LIBS_PATH,
    QEMU_PATH,
    QTRACE_PATH,
)


TRACE_MAX_BB_ADDRS = 0x1000


class TRACE_REASON(enum.Enum):
    trace_full = 0
    trace_syscall_start = 1
    trace_syscall_end = 2
    trace_async = 3


class SYSCALL_START_DATA(ctypes.Structure):
    _fields_ = [
        ("syscall_a1", ctypes.c_uint64),
        ("syscall_a2", ctypes.c_uint64),
        ("syscall_a3", ctypes.c_uint64),
        ("syscall_a4", ctypes.c_uint64),
        ("syscall_a5", ctypes.c_uint64),
        ("syscall_a6", ctypes.c_uint64),
        ("syscall_a7", ctypes.c_uint64),
        ("syscall_a8", ctypes.c_uint64),
    ]

    def __getitem__(self, key):
        return getattr(self, self._fields_[key][0])


class SYSCALL_DATA(ctypes.Union):
    _fields_ = [
        ("syscall_start_data", SYSCALL_START_DATA),
        ("syscall_ret", ctypes.c_int64),
    ]


class TRACE_INFO(ctypes.Structure):
    _fields_ = [("syscall_num", ctypes.c_int64), ("syscall_data", SYSCALL_DATA)]


class TRACE_HEADER(ctypes.Structure):
    _fields_ = [
        ("reason", ctypes.c_uint),
        ("num_addrs", ctypes.c_uint64),
        ("info", TRACE_INFO),
    ]


class TRACE(ctypes.Structure):
    _fields_ = [
        ("header", TRACE_HEADER),
        ("bb_addrs", ctypes.c_uint64 * TRACE_MAX_BB_ADDRS),
    ]


class TraceMachine:
    def __init__(self, argv, *, gdb_client=None):
        if gdb_client is None:
            gdb_client = gdb_minimal_client

        self.argv = argv
        self.gdb_client = gdb_client
        self.trace = []
        self.maps = {}
        self.async_flushing = threading.Semaphore(0)

        self.trace_socket = None
        self.gdb = None
        self.std_streams = None

    @property
    def breakpoints(self):
        result = []
        for name in dir(self):
            if name == "breakpoints":
                continue
            value = getattr(self, name)
            if hasattr(value, "gdb_breakpoint_address"):
                result.append(value)
        return result

    def start(self):
        process = subprocess.Popen(
            [
                LD_PATH,
                "--library-path",
                LIBS_PATH,
                QEMU_PATH,
                "-g",
                "1234",
                "-plugin",
                QTRACE_PATH,
                *self.argv,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.trace_socket = create_connection(("localhost", 4242))
        self.gdb = self.gdb_client(("localhost", 1234), self)
        self.std_streams = (process.stdin, process.stdout, process.stderr)

    def run(self):
        self.start()
        self.update_maps()

        for callback in self.breakpoints:
            self.gdb.add_breakpoint(callback.gdb_breakpoint_address, callback)

        self.gdb.async_continue()

        stdin, stdout, stderr = self.std_streams

        r_list = [self.trace_socket, self.gdb.socket, *filter(None, [stdout, stderr])]
        w_list = []
        x_list = []
        num_bytes = array.array("i", [0])

        while r_list:
            r_available, w_available, x_available = select.select(
                r_list, w_list, x_list
            )

            for r in r_available:
                if r == self.trace_socket:
                    data = os.read(r.fileno(), ctypes.sizeof(TRACE_HEADER))
                    if data:
                        trace_header = TRACE_HEADER.from_buffer_copy(data)
                        bb_addr_type = dict(TRACE._fields_)["bb_addrs"]._type_
                        bb_addrs_size = trace_header.num_addrs * ctypes.sizeof(
                            bb_addr_type
                        )

                        trace_data = b""
                        while len(trace_data) < bb_addrs_size:
                            trace_data += os.read(
                                r.fileno(), bb_addrs_size - len(trace_data)
                            )
                        trace_addrs = (
                            trace_header.num_addrs * bb_addr_type
                        ).from_buffer_copy(trace_data)

                        reason = TRACE_REASON(trace_header.reason)

                        for address in trace_addrs:
                            self.on_basic_block(address)

                        if reason == TRACE_REASON.trace_full:
                            self.ack()

                        elif reason == TRACE_REASON.trace_syscall_start:
                            syscall_nr = trace_header.info.syscall_num
                            syscall_definition = syscalls["x86_64"][syscall_nr]
                            syscall_args = syscall_definition[2:]
                            args = list(
                                trace_header.info.syscall_data.syscall_start_data
                            )[: len(syscall_args)]
                            self.on_syscall_start(syscall_nr, *args)

                        elif reason == TRACE_REASON.trace_syscall_end:
                            syscall_nr = trace_header.info.syscall_num
                            ret = trace_header.info.syscall_data.syscall_ret
                            self.on_syscall_end(syscall_nr, ret)

                        elif reason == TRACE_REASON.trace_async:
                            self.ack()
                            self.async_flushing.release()

                elif r == self.gdb.socket:
                    data = self.gdb.async_recv()

                elif r == stdout:
                    fcntl.ioctl(r.fileno(), termios.FIONREAD, num_bytes)
                    data = os.read(r.fileno(), num_bytes[0])
                    self.on_output(1, data)

                elif r == stderr:
                    fcntl.ioctl(r.fileno(), termios.FIONREAD, num_bytes)
                    data = os.read(r.fileno(), num_bytes[0])
                    self.on_output(2, data)

                if not data:
                    r_list.remove(r)

    def ack(self):
        os.write(self.trace_socket.fileno(), (0).to_bytes(8, "little"))

    def request_flush(self):
        os.write(self.trace_socket.fileno(), (1).to_bytes(8, "little"))
        self.async_flushing.acquire()

    def request_maps(self):
        os.write(self.trace_socket.fileno(), (2).to_bytes(8, "little"))

    def update_maps(self):
        self.request_maps()
        self.maps.clear()
        for line in self.trace_socket.recv(0x10000).decode().strip().split("\n"):
            address, permissions, offset, device, inode, pathname = line.split(" ", 5)
            start_address, end_address = address.split("-")
            start_address = int(start_address, 16)
            end_address = int(end_address, 16)
            offset = int(offset, 16)
            inode = int(inode)
            pathname = pathname.strip()

            store = False
            store |= start_address > 0x4000000000 and end_address < 0x5000000000
            store |= pathname in {
                "[heap]",
                "[stack]",
                "[vvar]",
                "[vdso]",
                "[vsyscall]",
                self.argv[0],
            }
            if store:
                mapping = (pathname, offset, permissions)
                self.maps[(start_address, end_address)] = mapping
        self.ack()

    def on_basic_block(self, address):
        self.trace.append(("bb", address))

    def on_syscall_start(self, syscall_nr, *args):
        self.trace.append(("syscall_start", syscall_nr, *args))
        self.ack()

    def on_syscall_end(self, syscall_nr, ret):
        self.trace.append(("syscall_end", syscall_nr, ret))
        self.ack()

    def on_output(self, fd, data):
        self.trace.append(("output", fd, data))

    def filtered_trace(self, filter_):
        if isinstance(filter_, str):
            filter_str = filter_
            filter_ = lambda event: event[0] == filter_str
        yield from (event for event in self.trace if filter_(event))


class LogTraceMachine(TraceMachine):
    def on_syscall_start(self, syscall_nr, *args):
        super().on_syscall_start(syscall_nr, *args)
        print(syscall_description("x86_64", syscall_nr, *args), end=" ")

    def on_syscall_end(self, syscall_nr, ret):
        super().on_syscall_end(syscall_nr, ret)
        print(syscall_description("x86_64", ret=ret).strip())

    def on_output(self, fd, data):
        super().on_output(fd, data)
        os.write(fd, data)
