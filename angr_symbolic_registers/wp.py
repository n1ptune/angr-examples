import angr
import claripy
p=angr.Project("angr_symbolic_registers",auto_load_libs=False)
state=p.factory.blank_state(addr=0x400a1f)
password1=claripy.BVS('password1',32)
password2=claripy.BVS('password2',32)
password3=claripy.BVS('password3',32)
state.regs.eax=password1
state.regs.ebx=password2
state.regs.edx=password3
sim=p.factory.simgr(state)
sim.explore(find=0x400a8c,avoid=0x400a76)
if sim.found:
    s1=sim.found[0].solver.eval(password1)
    s2=sim.found[0].solver.eval(password2)
    s3=sim.found[0].solver.eval(password3)
    result=format(s1,"x")+" "+format(s2,"x")+" "+format(s3,"x")
    print("yes!! result is {}".format(result))
else:
    print("no")
