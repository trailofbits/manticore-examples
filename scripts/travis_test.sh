#!/bin/bash

RV=1

# Google 2016 Unbreakable
cd google2016_unbreakable
python win.py | tee unbreakable.log
RESULTS=$(grep "CTF{" unbreakable.log)
if [[ "${RESULTS}" == CTF{0The1Quick2Brown3Fox4Jumped5Over6The7Lazy8Fox9}eeeeeeeeeeeeeeee ]]
then
    echo "Google 2016 Unbreakable passed"
    RV=0
else
    echo "Google 2016 Unbreakable failed"
fi
cd ..

exit ${RV}
