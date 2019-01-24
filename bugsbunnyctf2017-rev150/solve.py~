from manticore.native import Manticore
import sys

prog = sys.argv[1]
params = sys.argv[2:]

"""
To run:
$ python rev150.py ./rev150 00000000000000000000

The symbolic execution will overwrite the integer value with some number from 0 to 99999999999999999999 (you know that there are only 20 digits from IDA Pro. The program increments until the correct value is found.

For testing purposes, the solution is 42813724579039578812.

Run time: 9:10.62
"""

m = Manticore(prog, params)

"""
Here, we are setting the initial password (from IDA Pro, we can deduce a majority of the digits). We know that the password consists of 20 digits, all of which must be numeric.
"""
with m.locked_context() as context: 
    context['password'] = 42810720579039578812

@m.hook(0x401be2)
def inject_password(state):
    """
    At this point, we inject our chosen password into the address holding the password inputted to the
    binary. The password is formatted to be 20 digits long.
    """
    with m.locked_context() as context:
        print("[+] injecting password: " + str(format(context['password'], '020')))
        state.cpu.write_bytes(state.cpu.RDI,str(format(context['password'],'020')))
        
@m.hook(0x401e5a)
def failed(state):
    """
    If the password is incorrect, we will increment the password (so long as it remains 20 digits) and
    return to the original point of injection.
    """
    with m.locked_context() as context:
        if (len(str(context['password'])) == 20):
            context['password'] += 1000000000000
            state.cpu.RIP = 0x401be2
            print("[-] incorrect password")
        else:
            print("[-] no password found")
            m.terminate()

@m.hook(0x401e49) 
def success(state):
    """
    If our password passes all of the checks, we can return it as the flag.
    """
    with m.locked_context() as context:
        print("[+] success. flag: BugsBunny{" + str(context['password']) + "}")
        m.terminate()
        
m.verbosity(1)
m.run()
