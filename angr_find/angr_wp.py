import angr
p=angr.Project("angr1",auto_load_libs=False)
state=p.factory.entry_state()
sim=p.factory.simgr(state)
sim.explore(find=0x4007c3,avoid=0x4007af)
if sim.found:
    print(sim.found[0].posix.dumps(0))
else:
    print("not found")
