import angr
import claripy

p=angr.Project("../dist/06_angr_symbolic_dynamic_memory",auto_load_libs=False)
state=p.factory.blank_state(addr=0x8048699)


passw1=claripy.BVS("passw1",8*8)
passw2=claripy.BVS("passw2",8*8)

point_buffer0=0xABCC8A4
point_buffer1=0xABCC8Ac

fake_buffer0=0xdeadbeaf
fake_buffer1=0xdeadbcaf

state.memory.store(point_buffer0,fake_buffer0,endness=p.arch.memory_endness)
state.memory.store(point_buffer1,fake_buffer1,endness=p.arch.memory_endness)

state.memory.store(fake_buffer0,passw1)
state.memory.store(fake_buffer1,passw2)

sim=p.factory.simgr(state)
sim.explore(find=0x8048759,avoid=0x8048747)
if sim.found:
    for i in sim.found:
        print("yes {0} {1}".format(i.solver.eval(passw1,cast_to=bytes).decode("utf-8"),i.solver.eval(passw2,cast_to=bytes).decode("utf-8")))
else:
    print("n000~~")
