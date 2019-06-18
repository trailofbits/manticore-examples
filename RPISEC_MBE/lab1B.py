#!/usr/bin/env python3
# -*- coding: utf-8 --

from manticore.native import Manticore

m = Manticore("./lab1B")
m.verbosity(1)

"""
This lab has 21 unique cases equivalent to
switch(0x1337d00d - input):
    case(1):
        ...
    case(2):
        ...
    ...
    case(21):
        ...

by setting our input to 0x1337d00d - 1, we ensure we will hit the first case
"""
m.context["password"] = 0x1337D00D - 1


@m.hook(0x8048A55)
def bad_password(state):
    """
    If this address is reached, the password check has failed. Luckily, there
    are a limited number of possible cases. We can decrement our input to reach
    the next case, then manually jump back to the switch
    """
    with m.locked_context() as context:
        print("[-] abandoning path (invalid password)")

        context["password"] -= 1
        state.cpu.EIP = 0x8048BF6


@m.hook(0x8048A4E)
def success(state):
    """
    If this code is reached, our password must have been correct. Dump our input
    when this address is reached.
    """
    with m.locked_context() as context:
        print("[+] found success path")
        print("[+] password: {}".format(context["password"]))
        m.terminate()


@m.hook(0x8048BF6)
def inject_data(state):
    """
    Instead of sending out input through stdin, it's more efficient to jump
    over calls to i/o functions like fgets or puts and inject our data
    manually onto the stack. Because these libc functions are so massive, this
    can give us significant performance improvements.
    """
    with m.locked_context() as context:
        # skip ahead several instructions to jump over puts/fgets/scanf
        state.cpu.EIP = 0x8048C52

        print("[+] injecting " + hex(context["password"]))
        state.cpu.EAX = context["password"]


m.run(procs=10)
