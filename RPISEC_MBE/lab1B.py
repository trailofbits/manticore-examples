#!/usr/bin/env python3
# -*- coding: utf-8 --

from manticore.native import Manticore

m = Manticore('./lab1B')
m.verbosity = 1
m.context['counter'] = 0x1337d00d - 1


@m.hook(0x8048A55)
def abandon_password(state):
    with m.locked_context() as context:
        print("[-] abandoning path (invalid password)")

        # reached failure branch - try again with the next case
        context['counter'] -= 1
        state.cpu.EIP = 0x8048BF6


@m.hook(0x8048A4E)
def success(state):
    with m.locked_context() as context:
        print("[+] found success path")
        print("[+] password: {}".format(context['counter']))
        m.terminate()


@m.hook(0x8048BF6)
def inject_data(state):
    with m.locked_context() as context:
        # skip calls to time/srand/puts/printf/scanf
        state.cpu.EIP = 0x8048C52

        print("[+] injecting " + hex(context['counter']))
        state.cpu.EAX = context['counter']


m.run(procs=10)
