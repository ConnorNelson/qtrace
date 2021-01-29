import time
import socket
import contextlib


def create_connection(address, *, num_attempts=8, sleep_time=1):
    for _ in range(num_attempts):
        with contextlib.suppress(ConnectionRefusedError, OSError):
            return socket.create_connection(address)
        time.sleep(sleep_time)
    else:
        raise ConnectionRefusedError("Failed to connect to qtrace's trace socket!")
