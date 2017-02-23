import angr

base = 0x400000

p = angr.Project('./crazy_serial')
e = p.factory.entry_state(addr=base+0x01129)

email = e.se.BVS('email', 0x18*8)
serial = e.se.BVS('serial', 0x1B*8)

e.memory.store(e.regs.rbp-0x230, email)
e.memory.store(e.regs.rbp-0x430, serial)

pg = p.factory.path_group(e)

to_avoid = [base+0x100F]

ex = pg.explore(find=base+0x1412, avoid=to_avoid)

f = pg.found[0].state
s = ex.found[0].state

print f.se.any_str(serial)

