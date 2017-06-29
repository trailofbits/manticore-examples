#!/bin/bash
set -o pipefail

RV=0

# Google 2016 Unbreakable
cd google2016_unbreakable
FAILED=0
time python win.py | tee unbreakable.log || FAILED=1
grep -q "CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}" unbreakable.log || FAILED=1
if [[ $FAILED -eq 0 ]]
then
    echo "Google 2016 Unbreakable passed"
else
    echo "Google 2016 Unbreakable failed"
    RV=1
fi
cd ..

# Manticore Challenge
cd manticore_challenge
FAILED=0
time python win.py | tee mcore_challenge.log || FAILED=1
grep -q "=MANTICORE==" mcore_challenge.log || FAILED=1
if [[ $FAILED -eq 0 ]]
then
    echo "Manticore Challenge passed"
else
    echo "Manticore Challenge failed"
    RV=1
fi
cd ..

# Exploit Generation Example
cd exploit_generation_example
python record.py ./bof AAAAAAAAAAAAAAAAAAAAAAA | tee exploit_gen_record.log
if grep -q "call eax" exploit_gen_record.log
then
    echo "Exploit Generation record passed"
else
    echo "Exploit Generation record  failed"
    RV=1
fi
python crash_analysis.py ./bof  -- AAAAAAAAAAAAAAAAAAAAAAA -- +++++++++++++++++++++++ | tee exploit_gen_analysis.log
if grep -q "The solution is:" exploit_gen_analysis.log
then
    echo "Exploit Generation analysis  passed"
else
    echo "Exploit Generation analysis failed"
    RV=1
fi
cd ..


exit ${RV}
