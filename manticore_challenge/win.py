from manticore.native import Manticore
from subprocess import check_output
import sys

"""
Leverages Manticore to solve the manticore challenge:
https://blog.trailofbits.com/2017/05/15/magic-with-manticore/

Author: @ctfhacker

python win.py
=MANTICORE==
real    0m52.039s
user    0m50.272s
sys     0m2.340s
"""

addrs = []

def get_exits():
    """ Extract exit calls from each check function using objdump """
    def addr(line):
        """ Get just the address from a line of objdump output """
        return int(line.split()[0][:-1], 16)

    exits_disasm = check_output("objdump -d manticore_challenge | grep exit", shell=True)
    exits = [addr(line) for line in exits_disasm.decode().split('\n')[2:-1]]
    for e in exits:
        yield e

m = Manticore('manticore_challenge')

buff_addr = None

@m.hook(0x4009a4)
def hook(state):
    """ Jump over `puts` and `fgets` calls """
    state.cpu.EIP = 0x4009c1

@m.hook(0x4009c8)
def hook(state):
    """ Inject symbolic buffer instead of fgets """
    global buff_addr
    buff_addr = state.cpu.RDI
    buffer = state.new_symbolic_buffer(12)
    state.cpu.write_bytes(buff_addr, buffer)

@m.hook(0x400981)
def hook(state):
    """ Finish all the checks, solve for the solution """
    res = ''.join(map(chr, state.solve_buffer(buff_addr, 12)))
    print(res) # =MANTICORE==
    state.abandon() # Be sure to abandon and not continue execution

def exit_hook(state):
    """ Abandon hook for each exit call """
    state.abandon()

"""
For each exit that we found in each of the checks,
add the exit_hook to that call
"""
for index, exit in enumerate(get_exits()):
    m.add_hook(exit, exit_hook)

m.verbosity = 0
m.workers = 1
m.should_profile = True
m.run()
