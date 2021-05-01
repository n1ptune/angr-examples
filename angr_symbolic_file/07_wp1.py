import angr
import claripy

p=angr.Project("../dist/07_angr_symbolic_file",auto_load_libs=False)

state=p.factory.blank_state(addr=0x80488EA)

filename='OJKSQYDP.txt'
file_size=64

passw1=claripy.BVS("passw1",file_size*8)

pwd_file=angr.storage.SimFile(filename,content=passw1,size=file_size)
state.fs.insert(filename,pwd_file)

sim=p.factory.simgr(state)

sim.explore(find=0x80489B0,avoid=0x8048996)

if sim.found:
    solution0 = sim.found[0].solver.eval(passw1, cast_to=bytes)
    print("[+] Success! Solution is: {0}".format(solution0.decode('utf-8')))
else:
    print("n0~~")
