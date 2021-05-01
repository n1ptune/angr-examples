import angr
import claripy

p=angr.Project("../dist/07_angr_symbolic_file",auto_load_libs=False)
state=p.factory.blank_state(addr=0x804893C)

passwd=claripy.BVS("passwd1",64*8)
state.memory.store(0x804A0A0,passwd)

sim=p.factory.simgr(state)

sim.explore(find=0x80489B0,avoid=0x8048996)
if sim.found:
    print(sim.found[0].solver.eval(passwd,cast_to=bytes).decode("utf-8"))
else:
    print("n0~~")
