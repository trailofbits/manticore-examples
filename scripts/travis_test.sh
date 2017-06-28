#!/bin/bash

RV=0

# Google 2016 Unbreakable
cd google2016_unbreakable
time python win.py | tee unbreakable.log
if grep -q "CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}" unbreakable.log
then
    echo "Google 2016 Unbreakable passed"
else
    echo "Google 2016 Unbreakable failed"
    RV=1
fi
cd ..

# Manticore Challenge
cd manticore_challenge
time python win.py | tee mcore_challenge.log
if grep -q "=MANTICORE==" mcore_challenge.log
then
    echo "Manticore Challenge passed"
else
    echo "Manticore Challenge failed"
    RV=1
fi
cd ..

exit ${RV}
