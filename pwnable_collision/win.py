#!/usr/bin/env python3.6
"""
pwnable - collision challenge

    $ python win.py 
    
    Solves collision challenge from pwnable.kr,
    using symbolic execution to determine edge cases that
    can trigger a hash collision.

"""

import sys
import subprocess
from manticore.native import Manticore

# initialize Manticore object with symbolic input in
# argv[1]. We can eventually solve for this through
# state.input_symbol
m = Manticore('./col', ['+' * 20])
m.context['solution'] = None


# add fail_state callback to abandon
# paths we don't care about
def fail_state(state):
    print("Fail state! Abandoning.")
    state.abandon()

for addr in [0x400c2f, 0x400be7, 0x400bac]:
    m.add_hook(addr, fail_state)


@m.hook(0x400ba6)
def skip_syscalls(state):
    """ skip error-checking syscalls """
    state.cpu.EIP = 0x400bfa


@m.hook(0x400c1c)
def success_state(state):
    """ since input is symbolicated in argv, we search in 
    state.input_symbols to find the label """

    argv1 = next(sym for sym in state.input_symbols if sym.name == 'ARGV1')
    if argv1:
        with m.locked_context() as context:
            context['solution'] = state.solve_one(argv1, 20) 
    
    m.terminate()

# run Manticore, and print solution
m.verbosity(2)
m.run()

print("EDGE CASE: ", m.context['solution'])
