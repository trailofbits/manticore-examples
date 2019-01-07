from manticore.native import Manticore
import r2pipe # pip install r2pipe

"""
Leverages Manticore to solve the manticore challenge:
https://blog.trailofbits.com/2017/05/15/magic-with-manticore/

Author: @ctfhacker
"""

addrs = []

r2 = r2pipe.open('manticore_challenge')
r2.cmd('aaa')
for x in range(11):
    dis = r2.cmd('pdf @ sym.check_char_{}'.format(x))
    entry = int(dis.split('\n')[4].split()[1], 16)
    for line in dis.split('\n'):
        # print(line)
        if 'exit' in line:
            exit_call = int(line.split()[2], 16)
        elif 'je 0x' in line:
            je_statement = int(line.split()[2], 16)

    addrs.append((entry, je_statement,  exit_call))

m = Manticore('manticore_challenge')

buff_addr = None


@m.hook(0x4009a4)
def hook(state):
    """ Jump over `puts` and `fgets` calls """
    state.cpu.EIP = 0x4009c1


@m.hook(0x4009c8)
def hook(state):
    """ Inject symbolic buffer instead of fgets """
    global buff_addr
    buff_addr = state.cpu.RDI
    print("Buf addr: {:x}".format(buff_addr))
    buffer = state.new_symbolic_buffer(12)
    state.cpu.write_bytes(buff_addr, buffer)


@m.hook(0x400981)
def hook(state):
    # print("Checking {:x}".format(buff_addr))
    res = ''.join(map(chr, state.solve_buffer(buff_addr, 12)))
    print(res)
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
m.workers = 1
m.run()
