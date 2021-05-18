import collections
import contextlib

from ..utils import create_connection

amd64 = {
    "regs": [
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "rbp",
        "rsp",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
        "rip",
        "eflags",
        "cs",
        "ss",
        "ds",
        "es",
        "fs",
        "gs",
        "st0",
        "st1",
        "st2",
        "st3",
        "st4",
        "st5",
        "st6",
        "st7",
        "fctrl",
        "fstat",
        "ftag",
        "fiseg",
        "fioff",
        "foseg",
        "fooff",
        "fop",
        "xmm0",
        "xmm1",
        "xmm2",
        "xmm3",
        "xmm4",
        "xmm5",
        "xmm6",
        "xmm7",
        "xmm8",
        "xmm9",
        "xmm10",
        "xmm11",
        "xmm12",
        "xmm13",
        "xmm14",
        "xmm15",
        "mxcsr",
    ],
    "endian": "little",
    "bits": 64,
}


class GDB:
    def __init__(self, address, *, arch=amd64):
        self.socket = create_connection(address)
        self.arch = arch
        self.registers = self.fetch_registers()
        self.breakpoints = collections.defaultdict(list)
        self.memory = Memory(self)

    def checksum(self, data):
        if isinstance(data, str):
            data = data.encode()
        return sum(data) % 256

    def send(self, cmd):
        checksum = self.checksum(cmd)
        self.socket.send(f"${cmd}#{checksum:02x}".encode())
        assert self.socket.recv(1) == b"+"

    def recv(self, ok=False):
        assert self.socket.recv(1) == b"$"
        result = b""
        while True:
            b = self.socket.recv(1)
            if b == b"#":
                break
            result += b
        checksum = int(self.socket.recv(2), 16)
        assert checksum == self.checksum(result)
        self.socket.send(b"+")
        if ok:
            assert result == b"OK"
        return result

    def detach(self):
        for address in self.breakpoints:
            self.send(f"z0,{address:x},2")
            self.recv(ok=True)
        self.send("D")
        self.recv(ok=True)
        self.socket.close()

    def step(self):
        self.send("s")
        assert self.recv() == b"S05"

    def fetch_registers(self, refresh=True):
        self.send("g")
        response = self.recv()
        hex_length = self.arch["bits"] >> 2
        self.registers = {
            reg: int.from_bytes(
                bytes.fromhex(response[i * hex_length : (i + 1) * hex_length].decode()),
                self.arch["endian"],
            )
            for i, reg in enumerate(self.arch["regs"])
        }
        return self.registers

    def fetch_memory(self, address, length):
        self.send(f"m{address:x},{length}")
        response = self.recv()
        return bytes.fromhex(response.decode())

    def add_breakpoint(self, address, callback):
        if address not in self.breakpoints:
            self.send(f"Z0,{address:x},2")
            self.recv(ok=True)
        self.breakpoints[address].append(callback)

    def handle_sigtrap(self):
        self.fetch_registers()
        current_breakpoints = self.breakpoints[self.rip]
        assert current_breakpoints
        for callback in current_breakpoints:
            callback()
        self.step()
        self.async_continue()

    def async_continue(self):
        self.send("c")

    def async_recv(self):
        response = self.recv()
        if response.startswith(b"W"):
            assert len(response) == 3
            code = int(response[1:], 16)
            return False
        elif response.startswith(b"S"):
            assert len(response) == 3
            code = int(response[1:], 16)
            assert code == 5
            self.handle_sigtrap()
            return True
        else:
            raise Exception(f"Unknown response from gdb: {response}")

    def __getitem__(self, key):
        if isinstance(key, str):
            with contextlib.suppress(KeyError):
                return self.registers[key]
        elif isinstance(key, slice):
            if key.step is None:
                return self.fetch_memory(key.start, key.stop - key.start)
        raise TypeError("Key must be a valid register or memory region")

    def __getattr__(self, name):
        with contextlib.suppress(KeyError):
            return self.registers[name]
        raise AttributeError(name)


class Memory:
    def __init__(self, gdb):
        self.gdb = gdb

    def __getitem__(self, key):
        if isinstance(key, slice):
            address = key.start
            length = key.stop - key.start
            return self.gdb.fetch_memory(address, length)
        raise KeyError()


def gdb_minimal_client(address, machine):
    return GDB(address)
