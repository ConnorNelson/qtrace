import os
import sys
import fcntl
import select
import termios
import array
import enum
import ctypes
import socket
import subprocess
import pathlib

from . import syscalls, LD_PATH, LIBS_PATH, QEMU_PATH, QTRACE_PATH


TRACE_MAX_BB_ADDRS = 0x1000


class TRACE_REASON(enum.Enum):
    trace_full = 0
    trace_syscall_start = 1
    trace_syscall_end = 2


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
    def __init__(self, argv, *, trace_socket=None, std_streams=(None, None, None)):
        self.argv = argv
        self.trace_socket = trace_socket
        self.std_streams = std_streams
        self.trace = []

    def start(self):
        process = subprocess.Popen(
            [
                LD_PATH,
                "--library-path",
                LIBS_PATH,
                QEMU_PATH,
                "-plugin",
                QTRACE_PATH,
                *self.argv,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.trace_socket = socket.create_connection(("localhost", 4242))
        self.std_streams = (None, process.stdout, process.stderr)

    def run(self):
        if not self.trace_socket:
            self.start()

        trace_socket = self.trace_socket
        stdin, stdout, stderr = self.std_streams

        r_list = [trace_socket, *filter(None, [stdout, stderr])]
        w_list = []
        x_list = []
        num_bytes = array.array("i", [0])

        while r_list:
            r_available, w_available, x_available = select.select(
                r_list, w_list, x_list
            )

            for r in r_available:
                if r == trace_socket:
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
                            pass

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

                        os.write(trace_socket.fileno(), b"\x00" * 8)

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

    def on_basic_block(self, address):
        self.trace.append(("bb", address))

    def on_syscall_start(self, syscall_nr, *args):
        self.trace.append(("syscall_start", syscall_nr, *args))

    def on_syscall_end(self, syscall_nr, ret):
        self.trace.append(("syscall_end", syscall_nr, ret))

    def on_output(self, fd, data):
        self.trace.append(("output", fd, data))

    def filtered_trace(self, filter_):
        if isinstance(filter_, str):
            filter_str = filter_
            filter_ = lambda event: event[0] == filter_str
        yield from (event for event in self.trace if filter_(event))


class LogTraceMachine(TraceMachine):
    def syscall_int_fmt(self, arg):
        if arg <= 0x100:
            return str(arg)
        elif (1 << 32) - 0x100 <= arg < (1 << 32):
            return str(arg | (-(arg & 0x80000000)))
        else:
            return hex(arg)

    def on_syscall_start(self, syscall_nr, *args):
        super().on_syscall_start(syscall_nr, *args)

        syscall_definition = syscalls["x86_64"][syscall_nr]
        syscall_name = syscall_definition[1]

        if syscall_name.startswith("sys_"):
            syscall_name = syscall_name[len("sys_") :]

        description_inner = ", ".join(self.syscall_int_fmt(arg) for arg in args)
        description = f"{syscall_name}({description_inner})"
        print(description, end=" ")

    def on_syscall_end(self, syscall_nr, ret):
        super().on_syscall_end(syscall_nr, ret)
        print("=", self.syscall_int_fmt(ret))

    def on_output(self, fd, data):
        super().on_output(fd, data)
        os.write(fd, data)
