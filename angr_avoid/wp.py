import angr
p=angr.Project("angr_avoid",auto_load_libs=False)
state=p.factory.entry_state()
sim=p.factory.simgr(state)
sim.explore(find=0x4006f6,avoid=0x4006df)
if sim.found:
    print("flag is:{}".format(sim.found[0].posix.dumps(0).decode("utf-8")))
else:
    print("oh no!")
