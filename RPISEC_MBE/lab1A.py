#!/usr/bin/env python3
# -*- coding: utf-8 --

from manticore.native import Manticore

m = Manticore('./lab1A')

m.verbosity(1)


@m.hook(0x8048B69)
def inject_user_name(state):
    # skip expensive calls to fgets/puts/scanf
    state.cpu.RIP = 0x8048C1E
    with m.locked_context() as context:
        user_name = 'test123'
        serial_placeholder = 0xdeadbeef

        # inject constrained variables
        user_address = state.cpu.ESP + 0x1c
        serial_address = state.cpu.ESP + 0x18
        context['user_address'] = user_address
        context['username'] = user_name
        print("[+] injecting symbolic username: 0x" + hex(user_address))
        print("[+] injecting placeholder serial: 0x" + hex(serial_address))
        state.cpu.write_bytes(user_address, user_name)
        state.cpu.write_int(serial_address, serial_placeholder)  # arbitrary placeholder data


@m.hook(0x8048B31)
def grab_serial(state):
    with m.locked_context() as context:
        print('[+] recovering serial')
        context['serial'] = state.cpu.read_int(state.cpu.EBP - 0x10)
        state.cpu.EAX = context['serial']


@m.hook(0x8048A23)
def skip_strcspn(state):
    print('[+] skipping call to strcspn')
    state.cpu.EIP = 0x8048A3E


@m.hook(0x8048A88)
def ptrace_failed(state):
    print('[!] ptrace failed!')
    m.terminate()


@m.hook(0x8048C36)
def success(state):
    with m.locked_context() as context:
        print("[+] found success path")
        serial = context['serial']
        username = context['username']
        print("[+] username: " + username)
        print("[+] serial #: {}".format(serial))
        m.terminate()


m.run(procs=10)
