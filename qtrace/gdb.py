from . import create_connection

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

    def checksum(self, data):
        if isinstance(data, str):
            data = data.encode()
        return sum(data) % 256

    def send(self, cmd):
        checksum = self.checksum(cmd)
        self.socket.send(f"${cmd}#{checksum:02x}".encode())
        assert self.socket.recv(1) == b"+"

    def recv(self):
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
        return result

    def continue_(self):
        self.send("c")

    def detach(self):
        self.send("D")
        assert self.recv() == b"OK"
        self.socket.close()

    def registers(self):
        if not hasattr(self, "_registers"):
            self.send("g")
            response = self.recv()
            hex_length = self.arch["bits"] >> 2
            self._registers = {
                reg: int.from_bytes(
                    bytes.fromhex(
                        response[i * hex_length : (i + 1) * hex_length].decode()
                    ),
                    self.arch["endian"],
                )
                for i, reg in enumerate(self.arch["regs"])
            }
        return self._registers

    def memory(self, address, length):
        self.send(f"m{address:x},{length}")
        response = self.recv()
        return bytes.fromhex(response.decode())

    def __getitem__(self, key):
        if isinstance(key, str):
            try:
                return self.registers()[key]
            except KeyError:
                pass
        elif isinstance(key, slice):
            if key.step is None:
                return self.memory(key.start, key.stop - key.start)
        raise TypeError("Key must be a valid register or memory region")
