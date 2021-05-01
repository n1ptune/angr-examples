import angr
import claripy

p=angr.Project("../dist/04_angr_symbolic_stack",auto_load_libs=False)

state=p.factory.blank_state(addr=0x8048697)

state.regs.ebp=state.regs.esp

state.regs.esp-=8

passw1=claripy.BVS("passw1",32)
passw2=claripy.BVS("passw2",32)

state.stack_push(passw1)
state.stack_push(passw2)

sim=p.factory.simgr(state)
sim.explore(find=0x80486E4,avoid=0x80486D2)
if sim.found:
    for i in sim.found:
        print("yes flag is {0} {1}".format(i.solver.eval(passw1),i.solver.eval(passw2)))
else:
    print("n0~~")
