#!/usr/bin/env python
# -*- coding: utf-8 --

from manticore.native import Manticore


m = Manticore('ais3_crackme', ['a'*30])

buffer_addr = 0
num_bytes = 30


@m.hook(0x4005cd)
def hook(state):
    print("fake 2 args EDI=2")
    state.cpu.EDI=0x2


@m.hook(0x4005f3)
def hook(state):
    print("retrieve buffer from rax")
    global buffer_addr
    # print state.cpu.read_int(state.cpu.RAX), 'yoo'
    # assert 0
    solution = state.new_symbolic_buffer(num_bytes)
    state.constrain(solution[0] == ord('a'))
    state.constrain(solution[1] == ord('i'))
    state.constrain(solution[2] == ord('s'))
    state.constrain(solution[3] == ord('3'))
    state.constrain(solution[4] == ord('{'))
    buffer_addr = state.cpu.read_int(state.cpu.RAX)
    m.context[1] = buffer_addr
    print("buffer addr : 0x" + hex(buffer_addr))
    state.cpu.write_bytes(buffer_addr, solution)


@m.hook(0x40060e)
def hook(state):
    print("fail path ....")
    state.abandon()


@m.hook(0x400602)
def hook(state):
    print("it is a win path")
    buffer_addr = m.context[1]
    res = ''.join(map(chr, state.solve_buffer(buffer_addr,num_bytes)))
    print("flag is : " + res)
    m.terminate()


m.verbosity(1)
m.run(procs=10)
