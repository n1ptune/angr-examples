import angr
import claripy

p=angr.Project("../dist/05_angr_symbolic_memory")

state=p.factory.blank_state(addr=0x8048601)

pass1=claripy.BVS("pass",8*8*4)

state.memory.store(0x0A1BA1C0,pass1)

sim=p.factory.simgr(state)

sim.explore(find=0x0804866D,avoid=0x0804865B)
if sim.found:
    for i in sim.found:
        print("flag is {}".format(i.solver.eval(pass1,cast_to=bytes).decode("utf-8")))
else:
    print("n0~~")
