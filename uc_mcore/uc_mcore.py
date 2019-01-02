#!/usr/bin/env python3
"""
uc_mcore.py

    Introduces the concept of underconstrained symbolic execution,
    using Manticore to symbolicate specific functions rather than a whole
    program. This eliminates unnecessary analysis, speeding up execution for
    tasks like correctness checking and cryptographic verification.

    For more information:
        https://www.usenix.org/node/190952

    TODO:
        - incorporate example models and respective binaries
        for cryptographic verification
        - README for usage and help
"""
import argparse
import logging
import importlib

from manticore.native import Manticore

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--binary", dest="binary", required=True,
                        help="Target ELF binary for symbolic execution")
    parser.add_argument("-s", "--symbol", dest="symbol", required=True,
                        help="Function symbol for analysis")
    parser.add_argument("-a", "--attach", dest="hook", required=False,
                        nargs="*", help="User-defined hook(s) to attach")
    parser.add_argument("-t", "--trace", action='store_true', required=False,
                        help="Set to execute instruction recording")
    parser.add_argument("-v", "--verbosity", dest="verbosity", required=False,
                        default=2, help="Set verbosity for Manticore")

    args = parser.parse_args()
    if args is None:
        parser.print_help()

    # initialize Manticore
    m = Manticore(args.binary)
    m.verbosity(args.verbosity)
    m.context['trace'] = []
    m.context['result'] = ''

    sym_addr = m.resolve(args.symbol)

    # TODO: dynamically load hooks with importlib
    
    # record trace throughout execution if specified by user 
    if args.trace:
        @m.hook(None)
        def record(state):
            pc = state.cpu.PC
            print(f"{hex(pc)}"),
            with m.locked_context() as context:
                context['trace'] += [pc]


    # we don't care about any other execution except at the specified function,
    # so once we finish in _start and enter main, skip to our symbol's address.
    @m.hook(m.resolve('main'))
    def skip_main(state):
        print(f"Skipping execution! Jumping to {args.symbol}")
        state.cpu.EIP = sym_addr


    # at target symbol, assuming target was compiled for x86_64 
    # we immediately symbolicate the arguments.
    @m.hook(sym_addr)
    def hook(state):
        print("Injecting symbolic buffer into args")

        buf1 = state.new_symbolic_buffer(4)
        state.cpu.write_bytes(state.cpu.RSI, buf1)

        buf2 = state.new_symbolic_buffer(4)
        state.cpu.write_bytes(state.cpu.RDI, buf2)


    # error-checking
    # TODO: high-level python Curve25519 scalar mult implementation
    @m.hook(0x4030a9)
    def hook(state):
        cpu = state.cpu
        result = state.solve_buffer(cpu.RSI, 32)
        print(result)
        m.context['result'] + chr(result)
        m.terminate()


    m.run()

if __name__ == "__main__":
    main()
