#!/usr/bin/env python3
"""
This is a hacky test script. It's littered with sleeps to make things work and
relies on dumb string processing to execute shell commands.
"""

from pwn import *
import os.path
import pathlib
import re
import tempfile
import IPython

# pwntools debugging
context.log_level = 'debug'

images_base = '../../images'
qemu = '../../qemu/build/arm-softmmu/qemu-system-arm'
gdb_path = '../../buildroot-2020.02.9/output/build/host-gdb-8.2.1/gdb/gdb'

# Survey target binary to list of memory regions to test against to determine
# if target binary is running in QEMU system
target = 'crashing-http-server'
e = ELF(target)
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
	-net nic -net user,hostfwd=tcp:127.0.0.1:2222-:2222,hostfwd=tcp:127.0.0.1:8080-:8080,hostfwd=tcp:127.0.0.1:1234-:1234 \
	-display none -nographic \
	-plugin file={pathlib.Path(__file__).parent.absolute() / "libqtrace.so"},{args} \
	-snapshot
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

def cmd(s):
	print('Executing: ' + s)
	p.sendline(s)
	sleep(0.25)
	return p.recvuntil('#')

# Note: This expects that netcat is installed on the system. Alternatively you
# could pipe files through your shell, read/write them on disk before and after
# launching, etc
def send_file(path, outfile=None):
	outfile = outfile or os.path.basename(path)

	# Open a socket on guest (forwarded through QEMU above)
	p.sendline('nc -l -p 2222 > ' + outfile)
	sleep(0.25)

	# Pipe the file over
	s = remote('127.0.0.1', 2222)
	s.send(open(path, 'rb').read())
	s.close()

	# Wait for shell to come back and mark the file executable
	p.recvuntil('#')

	cmd('chmod +x ' + outfile)

def recv_file(path, outfile=None):
	outfile = outfile or os.path.basename(path)

	# Open a socket on guest (forwarded through QEMU above)
	p.sendline('cat ' + path + ' | nc -l -p 2222 -c')
	sleep(0.25)

	# Pipe the file over
	s = remote('127.0.0.1', 2222)
	open(outfile, 'wb').write(s.recvall())
	s.close()

	# Wait for shell to come back
	p.recvuntil('#')


# Enable core dumps
cmd('ulimit -c unlimited')
cmd('echo "core" > /proc/sys/kernel/core_pattern')

# Launch GDB server
cmd('gdbserver --multi 0.0.0.0:1234 &')

# Launch crashing HTTP Server, serve on port 8080
send_file('crashing-http-server')
cmd('./crashing-http-server -p 8080 &')

# Get crashing-http-server pid
pid = int(re.findall(r'TARGET_PID=(\d+)', cmd("echo TARGET_PID=$!").decode('utf-8'))[0])

# Fire up gdb to start collecting core dumps
coredump_addr = e.symbols['handle_connection']
script_src = f'''
set pagination off
target extended-remote 127.0.0.1:1234
attach {pid}
break *{hex(coredump_addr)}
commands
generate-core-file {target + '.core'}
continue
end
continue
'''
gdb_script_fd = tempfile.NamedTemporaryFile('w')
gdb_script_fd.write(script_src)
gdb_script_fd.flush()
gdb_process = process(gdb_path + ' -x ' + gdb_script_fd.name, True)

# Manually decide when to end things...
# IPython.embed()

# Use debug output to trace (FIXME: integrate with existing binary trace stream, not this text parsing)
while True:
	l = p.recvline()
	syscall_m = re.findall(r'syscall\((\d+)\)', l.decode('utf-8'))
	if syscall_m:
		print('syscall:' + str(syscall_m))
	exec_m = re.findall(r'exec\((0x[a-fA-F0-9]+)\)', l.decode('utf-8'))
	if exec_m:
		print('exec:' + str(exec_m))

gdb_process.kill()
p.kill()
