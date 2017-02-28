import angr
import simuvex

def nothing(state):
    pass

def _strlen(state):
    arg = state.regs.rdi
    i = 1
    #max chars 0x100
    while i<= 0x100:
        c = state.se.any_int(state.memory.load(arg+i, 1))
        if c == 0:
            break
        i +=1
    return i

global addr
addr = 0x5000000000000000

class newptr(simuvex.SimProcedure):
    def run(self, dst, src):
        global addr

        self.state.regs.rdi = src
        length = _strlen(self.state)
        aof = self.state.memory.load(src, length)
        addr += 0x1000
        self.state.memory.store(addr, aof)
        self.state.memory.store(dst, addr)
        #print self.state.se.any_str(self.state.memory.load(self.state.memory.load(self.state.regs.rbp-0xB0), length)).encode('hex')

class getlen(simuvex.SimProcedure):
    def run(self, ptrptr):
        ptr = self.state.se.any_int(self.state.memory.load(ptrptr))
        self.state.regs.rdi = ptr
        length = _strlen(self.state)
        return length
        
class getabsolute(simuvex.SimProcedure):
    def run(self, ptrptr , idx):
        ptr = self.state.se.any_int(self.state.memory.load(ptrptr)) + self.state.se.any_int(idx)
        return ptr

class strlen(simuvex.SimProcedure):
    def run(self, aof):
        self.state.regs.rdi = aof
        length = _strlen(self.state)
        return length

class getptr(simuvex.SimProcedure):
    def run(self, ptrptr):
        ptr = self.state.se.any_int(self.state.memory.load(ptrptr))
        return ptr

base = 0x400000

p = angr.Project('./bomb', load_options={'auto_load_libs':False})
s = p.factory.blank_state(addr=base+0x19A5, remove_options={simuvex.o.LAZY_SOLVES})


#p.hook(base+0x1560, nothing)
#p.hook(base+0x14E0, nothing)
p.hook(base+0x1550, newptr)
p.hook(base+0x1420, getlen)
p.hook(base+0x1590, getabsolute)
p.hook(base+0x1480, strlen)
p.hook(base+0x1530, getptr)
#p.hook(base+0x)

pg = p.factory.path_group(s)
to_avoid = [base+0x184B]
pg.explore(find=base+0x1C34, avoid=to_avoid)

f = pg.found[0].state

print (f.se.any_str(f.memory.load(f.regs.rbp-0x90)))
#print f.se.any_str(f.memory.load(f.memory.load(f.regs.rbp-0xB0), 0x20)).encode('hex')



