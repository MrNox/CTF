import sys
import angr

p = angr.Project('catalyst')
e = p.factory.blank_state(addr=0x00400CDD)

user_addr = 0x10000000
user_value = e.se.BVS('pass', 40*8)

e.memory.store(user_addr, user_value)
e.regs.rdi = user_addr
e.se._solver.timeout = 0x30000

pg = p.factory.path_group(e)

to_avoid = [0x04006D0, 0x0400750]
pg.explore(find=0x0400D90, avoid=to_avoid)

if len(pg.found) == 0:
    print "not found anything"
    sys.exit()

s = pg.found[0].state

print "user:",
print s.se.any_str(user_value)

