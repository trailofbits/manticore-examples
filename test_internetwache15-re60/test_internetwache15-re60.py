def test():
    from manticore.native import Manticore

    if __name__ == "__main__":
        binary = "./filechecker"
    else:
        binary = "./test_internetwache15-re60/filechecker"

    m = Manticore(binary)
    m.context["solved"] = False

    @m.hook(0x40067A)
    def skip_file_check(state):
        print("Skipping file checking")
        print("Changing PC from {:x} to {:x}".format(0x40067A, 0x4006CA))
        state.cpu.PC = 0x4006CA

    # ignore file operations
    @m.hook(0x4006E1)
    def skip_read_file(state):
        print("Skipping file reading")
        print("Changing PC from {:x} to {:x}".format(0x4006E1, 0x400709))
        state.cpu.PC = 0x400709

    # inject symbolic value at location on stack of fgetc
    @m.hook(0x400709)
    def use_symbolic_password(state):
        context = state.context
        flag = context.setdefault("flag", [])
        count = len(flag)
        char = state.new_symbolic_value(32, "flag.{}".format(count))
        state.constrain(char < 0x100)
        state.constrain(char > 0)

        state.cpu.write_int(state.cpu.RBP - 0x18, char, 32)
        flag.append(char)

    # incorrect path
    @m.hook(0x400732)
    def failure(state):
        print("Found fail path")
        state.abandon()

    # print success
    @m.hook(0x400743)
    def success(state):
        print("Found success path")
        context = state.context
        ans = ""
        for i in context["flag"]:
            ans += chr(state.solve_one(i))

        print(ans)
        if ans == "IW{FILE_CHeCKa}":
            with m.locked_context() as locked:
                locked["solved"] = True
        m.kill()

    print("Start")
    m.run()

    assert m.context["solved"]


if __name__ == "__main__":
    test()
