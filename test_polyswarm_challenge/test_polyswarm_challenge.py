def test():
    #!/usr/bin/env python
    # -*- coding: utf-8 -*-

    __author__ = "Raz0r"
    __email__ = "me@raz0r.name"

    """
    This is a solution to the PolySwarm's smart contract hacking challenge done with manticore.
    Please refer to https://raz0r.name/writeups/polyswarm-smart-contract-hacking-challenge-writeup/ for a complete walk through.
    """

    import binascii
    from manticore.ethereum import ManticoreEVM, ABI

    m = ManticoreEVM()
    m.context["solved"] = False

    # Set up accounts with original addresses
    owner_account = m.create_account(
        balance=1000, name="owner", address=0xBC7DDD20D5BCEB395290FD7CE3A9DA8D8B485559
    )
    attacker_account = m.create_account(
        balance=1000,
        name="attacker",
        address=0x762C808237A69D786A85E8784DB8C143EB70B2FB,
    )
    cashmoney_contract = m.create_account(
        balance=1000,
        name="CashMoney",
        address=0x64BA926175BC69BA757EF53A6D5EF616889C9999,
    )

    # Create WinnerLog contract using its init bytecode
    file = ""
    if __name__ == "__main__":
        file = "winnerlog.bin"
    else:
        file = "test_polyswarm_challenge/winnerlog.bin"

    with open(file, "rb") as f:
        bytecode = f.read()

    winnerlog_contract = m.create_contract(
        init=bytecode,
        owner=owner_account,
        name="WinnerLog",
        address=0x2E4D2A597A2FCBDF6CC55EB5C973E76AA19AC410,
    )

    # Allow cashmoney_contract to call logWinner() on winnerlog_contract
    m.transaction(
        caller=owner_account,
        address=winnerlog_contract,
        data=binascii.unhexlify(
            b"c3e8512400000000000000000000000064ba926175bc69ba757ef53a6d5ef616889c9999"
        ),
        value=0,
    )

    # Prepare symbready_statesand call logWinner() with that symbolic buffer
    symbolic_data = m.make_symbolic_buffer(64)
    calldata = ABI.function_call(
        "logWinner(address,uint256,bytes)", attacker_account, 0, symbolic_data
    )
    m.transaction(
        caller=cashmoney_contract,
        address=winnerlog_contract,
        data=calldata,
        value=0,
        gas=10000000,
    )

    # Look for a running state that is not reverted
    for state in m.ready_states:
        world = state.platform
        result = state.solve_one(symbolic_data)
        print("[+] FOUND: {}".format(binascii.hexlify(result)))
        with m.locked_context() as context:
            context["solved"] = True
        break
    assert m.context["solved"]


if __name__ == "__main__":
    test()
