#!/usr/bin/env python3
from pwn import *
import os.path
import pathlib

# pwntools debugging
context.log_level = 'debug'

images_base = '../../images'
qemu = '../../qemu/build/arm-softmmu/qemu-system-arm'

# Survey target binary to list of memory regions to test against to determine
# if target binary is running in QEMU system
e = ELF('crashing-http-server')
args = ''
for s in ['main']:
	addr = e.symbols[s]
	args += 'arg="%x=%s"' % (addr ,b64e(e.read(addr, 32)))

# QEMU launch params
cmd = f'''{qemu} \
	-M vexpress-a9 \
	-kernel {images_base}/zImage \
	-dtb {images_base}/vexpress-v2p-ca9.dtb \
	-drive file={images_base}/rootfs.qcow2,if=sd \
	-append "root=/dev/mmcblk0 console=ttyAMA0,115200" \
	-net nic -net user,hostfwd=tcp:127.0.0.1:2222-:2222,hostfwd=tcp:127.0.0.1:8080-:8080 \
	-display none -nographic \
	-plugin file={pathlib.Path(__file__).parent.absolute() / "libqtrace.so"},{args}
'''

# Launch QEMU system
p = process(cmd, True)

# Connect to tracer
sleep(0.5)
tracer = remote('127.0.0.1', 4242)

# Wait for login prompt
p.recvuntil('login:')
p.sendline('root')
p.recvuntil('#')

# Note: This expects that netcat is installed on the system. Alternatively you
# could pipe files through your shell, read/write them on disk before and after
# launching, etc
def send_file(path, outfile=None):
	outfile = outfile or os.path.basename(path)

	# Open a socket on guest (forwarded through QEMU above)
	p.sendline('nc -l -p 2222 > ' + outfile)
	sleep(0.125)

	# Pipe the file over
	s = remote('127.0.0.1', 2222)
	s.send(open(path, 'rb').read())
	s.close()

	# Wait for shell to come back and mark the file executable
	p.recvuntil('#')
	p.sendline('chmod +x ' + outfile)
	p.recvuntil('#')

def recv_file(path, outfile=None):
	outfile = outfile or os.path.basename(path)

	# Open a socket on guest (forwarded through QEMU above)
	p.sendline('cat ' + path + ' | nc -l -p 2222 -c')
	sleep(0.125)

	# Pipe the file over
	s = remote('127.0.0.1', 2222)
	open(outfile, 'wb').write(s.recvall())
	s.close()

	# Wait for shell to come back
	p.recvuntil('#')

def cmd(s):
	print('Executing: ' + s)
	p.sendline(s)
	p.recvuntil('#')

# Enable core dumps
cmd('ulimit -c unlimited')
cmd('echo "core" > /proc/sys/kernel/core_pattern')

# Launch crashing HTTP Server, serve on port 8080
send_file('crashing-http-server')
cmd('./crashing-http-server -p 8080')

p.kill()
