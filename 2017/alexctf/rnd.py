import binascii
from ctypes import CDLL
import sys

def rol(byte, count):
    while count > 0:
        byte = (byte << 1 | byte >> 31) & 0xFFFFFFFF
        count -= 1
    return byte

def ror(byte, count):
    while count > 0:
        byte = (byte >> 1 | byte << 31) & 0xFFFFFFFF
        count -= 1
    return byte

def bswap(value):
    return (rol(value, 8) & 0x00FF00FF) | (ror(value, 8) & 0xFF00FF00)


dwords = [
    0x55EB052A,
    0x0EF76C39,
    0xCC1E2D64,
    0x0C7B6C6F5,
    0x26941BFA,
    0x260CF0F3,
    0x10D4CAEF,
    0x0C666E824,
    0x0FC89459C,
    0x2413073A
]


libc = CDLL('/lib/x86_64-linux-gnu/libc-2.23.so')
user = 'catalyst_ceo'

libc.srand(0x454d3e2e)

buff = ''
for dd in dwords:
    rand = libc.rand()
    hx = '%x' % bswap((dd + rand) & 0xFFFFFFFF)
    buff += hx.decode('hex')
    
print '[*] User: %s' % user
print '[*] Password: %s' % buff
