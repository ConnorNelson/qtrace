import time
import socket
import contextlib


def create_connection(address, *, num_attempts=64, sleep_time=0.001):
    for _ in range(num_attempts):
        with contextlib.suppress(ConnectionRefusedError, OSError):
            return socket.create_connection(address)
        time.sleep(sleep_time)
    else:
        raise ConnectionRefusedError()
