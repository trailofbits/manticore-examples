#!/usr/bin/env python3
"""
uc_mcore.py

    Introduces the concept of underconstrained symbolic execution,
    using Manticore to symbolically execute specific functions rather than a whole
    program. This eliminates unnecessary analysis, speeding up execution for
    tasks like correctness checking and cryptographic verification.

    For more information:
        https://www.usenix.org/node/190952

"""
import os.path
import argparse

from ctypes import cdll
from manticore.native import Manticore

# initialize FFI through shared object
obj = 'tweetnacl.so'
obj_path = os.path.dirname(os.path.abspath(__file__)) + os.path.sep + obj
lib = cdll.LoadLibrary(obj_path)


def _wrap_func(lib, funcname, restype, argtypes):
    """ helper method for calling through ctypes """
    func = lib.__getattr__(funcname)
    func.restype = restypes
    func.argtypes = argtypes
    return func


def concrete_model(state, **kwargs):
    """ a model to be called through invoke_model() 
    in order to execute function without symbolic interpreter."""

    # retrieve symbol name from context
    with m.locked_context() as context:
        func = context['syms']
        _wrap_func(lib, func, None, **kwargs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--binary", dest="binary", required=True,
                        help="Target ELF binary for symbolic execution")
    parser.add_argument("-s", "--symbol", dest="symbol", required=True,
                        help="Function symbol(s) for equivalence analysis")
    parser.add_argument("-t", "--trace", action='store_true', required=False,
                        help="Set to execute instruction recording")
    parser.add_argument("-v", "--verbosity", dest="verbosity", required=False,
                        default=2, help="Set verbosity for Manticore")

    # parse or print help
    args = parser.parse_args()
    if args is None:
        parser.print_help()

    # initialize Manticore
    m = Manticore(args.binary)
    m.context['trace'] = [] 
    m.context['sym'] = ""

    # save symbol and resolve for address
    with m.locked_context() as context:
        context['sym'] = args.symbol 
        sym_addr = m.resolve(context['sym'])

    # record trace throughout execution if specified by user 
    if args.trace:
        @m.hook(None)
        def record(state):
            pc = state.cpu.PC
            print(f"{hex(pc)}"),
            with m.locked_context() as context:
                context['trace'] += [pc]

    # address location for arg registers
    rdi_addr = 0
    rsi_addr = 0

    # we don't care about any other execution except at the specified function,
    # so once we finish in _start and enter main, skip to our symbol's address.
    @m.hook(m.resolve('main'))
    def skip_main(state):
        print(f"Skipping execution! Jumping to {args.symbol}")
        state.cpu.EIP = sym_addr


    # at target symbol, assuming target was compiled for x86_64 
    # we immediately symbolicate the arguments. The calling convention
    # looks as so:
    # arg1: rdi, arg2: rsi, arg3: rdx
    @m.hook(sym_addr)
    def sym(state):
        """ create symbolic args with RSI and RDI
        to perform SE on function """

        print("Injecting symbolic buffer into args")
        rdi_addr = state.cpu.RDI
        rsi_addr = state.cpu.RSI

        rdi_buf = state.new_symbolic_buffer(32)
        state.cpu.write_bytes(rdi_addr, rdi_buf)
        
        rsi_buf = state.new_symbolic_buffer(32)
        state.cpu.write_bytes(rsi_addr, rsi_buf)

    
    def exec_concrete(state):
        """ hook that is attached for functions to be executed natively without
        Manticore SE """
        state.invoke_model(concrete_model)

    for addr in []:
        m.add_hook(addr, exec_concrete)

    # run manticore
    m.verbosity(args.verbosity)
    m.run()
    print("Done! Total instructions:", len(m.context['trace']))


if __name__ == "__main__":
    main()
