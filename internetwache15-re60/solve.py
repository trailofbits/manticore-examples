from manticore import Manticore

m = Manticore('filechecker')
with m.locked_context() as context:
    context['count'] = 0


@m.hook(0x40067a)
def skip_file_check(state):
    print("Skipping file checking")
    print("Changing PC from {:x} to {:x}".format(0x40067a, 0x4006ca))
    state.cpu.PC = 0x4006ca


@m.hook(0x400709)
def use_symbolic_password(state):
    with m.locked_context() as context:
        count = context['count']
        print('Adding symbolic flag.{}'.format(count))
        char = state.new_symbolic_value(32, 'flag.{}'.format(count))
        state.constrain(char < 0x100)
        state.constrain(char > 0)

        state.cpu.write_int(state.cpu.RBP - 0x18, char, 32)
        context['flag.{}'.format(count)] = char
        context['count'] += 1


@m.hook(0x4006e1)
def skip_read_file(state):
    print("Skipping file reading")
    print("Changing PC from {:x} to {:x}".format(0x4006e1, 0x400709))
    state.cpu.PC = 0x400709


@m.hook(0x400732)
def failure(state):
    print("Found fail path")
    state.abandon()


@m.hook(0x400743)
def success(state):
    print("Found success path")
    with m.locked_context() as context:
        ans = ''
        for i in range(context['count']):
            char = context['flag.{}'.format(i)]
            ans += chr(state.solve_one(char))

    print(ans)
    m.terminate()


print("Start")
m.run(procs=10)
