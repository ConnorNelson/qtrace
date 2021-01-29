import time
import socket
import contextlib


class GDB:
    def __init__(self, host, port):
        address = (host, port)
        for _ in range(10):
            with contextlib.suppress(ConnectionRefusedError, OSError):
                self.socket = socket.create_connection(address)
                break
            time.sleep(1)
        else:
            raise ConnectionRefusedError("Failed to connect to qtrace's gdb socket!")

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
