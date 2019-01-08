# pwnable - collision challenge

> Daddy told me about cool MD5 hash collision today.
> I wanna do something like that too!
> 
> See challenge: http://pwnable.kr/play.php

The concrete solution for this challenge would be to induce a hash collision by doing some math 
and figuring out integers that are in total equal to 0x21DD09EC.

With Manticore, we can instead have a solver compute concrete inputs that satisfy the constraint for the path that reveals
the flag. Through symbolic execution, we can have various edge cases that causes a hash collision and triggers the code path,
but may not be inputs that the program may be able to read.

For example:

```
$ ./col `echo -n -e "\xf5\x15^\x80\xfc?\x01\xd7@\xe1{C@\xfd\xfeB{\xd5\x02D"`
s0me_fl4g
```
