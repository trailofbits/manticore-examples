#!/usr/bin/env python
# -*- coding: utf-8 --


def test():
    from manticore.native import Manticore

    m = Manticore("test_ais3_crackme/ais3_crackme", ["a" * 30])

    buffer_addr = 0
    num_bytes = 24
    with m.locked_context() as w:
        w[1] = False

    @m.hook(0x4005CD)
    def hook(state):
        print("fake 2 args EDI=2")
        state.cpu.EDI = 0x2

    @m.hook(0x4005F3)
    def hook(state):
        print("retreive buffer from rax")
        global buffer_addr
        # print state.cpu.read_int(state.cpu.RAX), 'yoo'
        # assert 0
        solution = state.new_symbolic_buffer(num_bytes)
        state.constrain(solution[0] == ord("a"))
        state.constrain(solution[1] == ord("i"))
        state.constrain(solution[2] == ord("s"))
        state.constrain(solution[3] == ord("3"))
        state.constrain(solution[4] == ord("{"))
        buffer_addr = state.cpu.read_int(state.cpu.RAX)
        with m.locked_context() as w:
            w[1] = buffer_addr
        print("buffer addr : %08x " % (buffer_addr))
        state.cpu.write_bytes(buffer_addr, solution)

    @m.hook(0x40060E)
    def hook(state):
        state.abandon()
        print("failure path")

    @m.hook(0x400602)
    def hook(state):
        print("win path: attemping to solve")
        with m.locked_context() as w:
            buffer_addr = w[1]
        res = "".join(map(chr, state.solve_buffer(buffer_addr, num_bytes)))
        print("flag: %s" % res)
        if res == "ais3{I_tak3_g00d_n0t3s}":
            with m.locked_context() as w:
                w[1] = True
        m.kill()

    m.verbosity = 1
    m.run()
    with m.locked_context() as w:
        assert w[1]


if __name__ == "__main__":
    test()
