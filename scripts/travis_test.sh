#!/bin/bash

RV=0

# Google 2016 Unbreakable
cd google2016_unbreakable
time python win.py | tee unbreakable.log
RAN_OK=${PIPESTATUS[0]}
grep -q "CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}" unbreakable.log
GOT_FLAG=$?
if [[ $RAN_OK && $GOT_FLAG ]]
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
RAN_OK=${PIPESTATUS[0]}
grep -q "=MANTICORE==" mcore_challenge.log
GOT_FLAG=$?
if [[ $RAN_OK && $GOT_FLAG ]]
then
    echo "Manticore Challenge passed"
else
    echo "Manticore Challenge failed"
    RV=1
fi
cd ..

exit ${RV}
