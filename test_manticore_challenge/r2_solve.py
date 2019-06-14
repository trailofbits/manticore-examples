from manticore.native import Manticore
import r2pipe  # pip install r2pipe

"""
Leverages Manticore to solve the manticore challenge:
https://blog.trailofbits.com/2017/05/15/magic-with-manticore/

Author: @ctfhacker
"""
file = ""
if __name__ == "__main__":
    file = "manticore_challenge"
else:
    file = "test_manticore_challenge/manticore_challenge"

addrs = []

r2 = r2pipe.open(file)
r2.cmd("aaa")
for x in range(0, 11):
    dis = r2.cmd("pdf @ sym.check_char_{}".format(x))
    dis = dis.decode()
    entry = int(dis.split("\n")[4].split()[1], 16)
    for line in dis.split("\n"):
        # print(line)
        if "exit" in line:
            exit_call = int(line.split()[2], 16)
        elif "je 0x" in line:
            je_statement = int(line.split()[2], 16)

    addrs.append((entry, je_statement, exit_call))

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
    buff_addr = state.cpu.RDI
    with m.locked_context() as context:
        context["buff_addr"] = state.cpu.RDI
    print("Buf addr: {:x}".format(buff_addr))
    buffer = state.new_symbolic_buffer(12)
    state.cpu.write_bytes(buff_addr, buffer)


@m.hook(0x400981)
def hook(state):
    # print("Checking {:x}".format(buff_addr))
    buff_addr = ""
    with m.locked_context() as context:
        buff_addr = context["buff_addr"]
    res = "".join(map(chr, state.solve_buffer(buff_addr, 12)))
    print(res)
    with m.locked_context() as context:
        if "=MANTICORE" in res:
            context["solved"] = True
    state.abandon()


"""
def entry_hook(state):
    sym_reg = state.new_symbolic_value(32)
    state.cpu.write_register('EDI', sym_reg)
    # m.add_hook(None, print_ip)
    # m.verbosity = 3
"""

"""
def je_hook(state):
    # print("je HOOK: Here: {}".format(hex(state.cpu.EIP)))
    print('constra', state.constraints)
    res = state.solve_one(state.cpu.read_register('EDI'))
    # res = state.solve_one(state.cpu.EDI)
    print(chr(res), res)
    state.cpu.BL = res
"""


def exit_hook(state):
    # print("EXIT HOOK: Here: {}".format(hex(state.cpu.EIP)))
    state.abandon()


for index, items in enumerate(addrs):
    entry, je_statement, exit_call = items
    # m.add_hook(je_statement, je_hook)
    m.add_hook(exit_call, exit_hook)

"""
def print_ip(state):
    if 0x400000 < state.cpu.RIP < 0x500000:
        print(hex(state.cpu.RIP))
"""

m.verbosity = 0
m.run()
assert m.context["solved"]
