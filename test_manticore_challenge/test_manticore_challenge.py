def test():
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

    file = ""
    if __name__ == "__main__":
        file = "manticore_challenge"
    else:
        file = "./test_manticore_challenge/manticore_challenge"

    addrs = []

    def get_exits():
        """ Extract exit calls from each check function using objdump """

        def addr(line):
            """ Get just the address from a line of objdump output """
            return int(line.split()[0][:-1], 16)

        exits_disasm = check_output("objdump -d %s | grep exit" % file, shell=True)
        exits_disasm = exits_disasm.decode()
        exits = [addr(line) for line in exits_disasm.split("\n")[2:-1]]
        for e in exits:
            yield e

    m = Manticore(file)
    m.context["solved"] = False

    buff_addr = None

    @m.hook(0x4009A4)
    def hook(state):
        """ Jump over `puts` and `fgets` calls """
        state.cpu.EIP = 0x4009C1

    @m.hook(0x4009C8)
    def hook(state):
        """ Inject symbolic buffer instead of fgets """
        with m.locked_context() as context:
            context["buff_addr"] = state.cpu.RDI
        buffer = state.new_symbolic_buffer(12)
        state.cpu.write_bytes(state.cpu.RDI, buffer)

    @m.hook(0x400981)
    def hook(state):
        """ Finish all the checks, solve for the solution """
        buff_addr = ""
        with m.locked_context() as context:
            buff_addr = context["buff_addr"]
        res = "".join(map(chr, state.solve_buffer(buff_addr, 12)))
        print("solution: " + res)  # =MANTICORE==
        with m.locked_context() as context:
            if "=MANTICORE" in res:
                context["solved"] = True
        state.abandon()  # Be sure to abandon and not continue execution

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
    assert m.context["solved"]


if __name__ == "__main__":
    test()
