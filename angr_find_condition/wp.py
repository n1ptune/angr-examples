import angr
p=angr.Project("angr_find_condition",auto_load_libs=False)
state=p.factory.entry_state()
sim=p.factory.simgr(state)
def success(state):
    if b"Good Job" in state.posix.dumps(1):
        return True
    else:
        return False
def fail(state):
    if b"Try again" in state.posix.dumps(1):
        return True
    else:
        return False
sim.explore(find=success,avoid=fail)
print("!!!flag is:{}".format(sim.found[0].posix.dumps(0).decode("utf-8")))
