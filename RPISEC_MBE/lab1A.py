#!/usr/bin/env python3
# -*- coding: utf-8 --

from manticore.native import Manticore

m = Manticore("./lab1A")

m.verbosity(1)


@m.hook(0x8048B69)
def inject_user_name(state):
    # skip over expensive calls to puts/fgets/scanf
    state.cpu.RIP = 0x8048C1E

    """
    Because we're skipping the call to fgets/scanf, we'll have to inject our
    data manually
    """
    with m.locked_context() as context:
        user_name = "test123"
        serial_placeholder = 0xDEADBEEF  # arbitrary placeholder number

        # inject variables
        username_address = state.cpu.ESP + 0x1C
        serial_address = state.cpu.ESP + 0x18
        context["username_address"] = username_address
        context["username"] = user_name
        print("[+] injecting symbolic username: 0x" + hex(username_address))
        print("[+] injecting placeholder serial: 0x" + hex(serial_address))
        state.cpu.write_bytes(username_address, user_name)
        state.cpu.write_int(serial_address, serial_placeholder)


@m.hook(0x8048B31)
def grab_serial(state):
    """
    This lab calculates a serial number from the provided username, and checks it
    against the provided serial number. By hooking the comparision, we can simply
    update our serial number in memory to match.
    """
    with m.locked_context() as context:
        print("[+] recovering serial")
        context["serial"] = state.cpu.read_int(state.cpu.EBP - 0x10)
        state.cpu.EAX = context["serial"]


@m.hook(0x8048A23)
def skip_strcspn(state):
    """
    strcspn is used to locate the newline character in our input. Because we're
    manually injecting our input, there will be no newline.
    """
    print("[+] skipping call to strcspn")
    state.cpu.EIP = 0x8048A3E


@m.hook(0x8048C36)
def success(state):
    """
    If this address is reached, we know the username/serial number are valid.
    When this address is reached, dump the username and corresponding serial number.
    """
    with m.locked_context() as context:
        print("[+] found success path")
        print("[+] username: " + context["username"])
        print("[+] serial #: {}".format(context["serial"]))
        m.terminate()


m.run(procs=10)
