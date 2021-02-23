import angr
import claripy
#claripy是angr的约束求解器
p=angr.Project("angr_args",auto_load_libs=False)
#声明一个9*8位的向量
args=claripy.BVS("argv1",9*8)
#将参数出传入
state=p.factory.entry_state(args=["./angr_args",args])
sim=p.factory.simgr(state)
sim.explore(find=0x4006a7,avoid=0x4006bb)
if sim.found:
    print("!!flag is:{}".format(sim.found[0].solver.eval(args,cast_to=bytes).decode("utf-8")))
else:
    print("sorry")
