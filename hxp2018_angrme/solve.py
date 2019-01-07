#!/usr/bin/env python3
# -*- coding: utf-8 --

from manticore.native import Manticore
from manticore.core.smtlib import operators

m = Manticore('./angrme')

max_length = 40  # maximum flag length (rough guess-timate)
m.verbosity(1)


@m.hook(0x555555555187)
def inject_symbolic_input(state):
    # skip expensive call to fgets
    state.cpu.RIP = 0x5555555551a0

    # manually inject symbolic variable in place of input
    with m.locked_context() as context:
        solution = state.new_symbolic_buffer(max_length)

        # constrain flag format
        state.constrain(solution[0] == ord('h'))
        state.constrain(solution[1] == ord('x'))
        state.constrain(solution[2] == ord('p'))
        state.constrain(solution[3] == ord('{'))

        # constrain characters to be printable ASCII or null byte
        for i in range(max_length):
            state.constrain(operators.OR(solution[i] == 0,
                                         operators.AND(ord(' ') <= solution[i], solution[i] <= ord('}'))))

        address = state.cpu.RSP + 0x30
        context['input_address'] = address
        print("[+] input address: " + hex(state.cpu.RSP + 0x30))
        state.cpu.write_bytes(address, solution)


@m.hook(0x555555556390)
def abandon(state):
    print("[-] abandoning path")
    state.abandon()


@m.hook(0x555555556370)
def success(state):
    with m.locked_context() as context:
        print("[+] found success path")
        address = context['input_address']
        flag = ''.join(map(chr, state.solve_buffer(address, max_length)))
        print("[+] flag: " + flag)
        m.terminate()


m.run(procs=10)
