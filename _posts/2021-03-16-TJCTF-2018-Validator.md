---
title: "TJCTF 2018 - Validator" 
date: 2021-03-16
classes: wide
categories:
 - reverse engineering
 - infosec
 - ctf
tags:
 - reverse engineering
 - ctf
---

# TJCTF 2018 - Validator

This challenge is from an old TJCTF competition. The file they gave us displays the message `Valid flag` if it recieves the correct flag.

* * *

The `file` command tells us that this is a 32 bit elf file.

![file_command.png](../assets/images/validator/2b3a62c94d1742e4b9ccb08cec1b61e2.png)

When we run `strings` we can see something that looks like the flag 

![strings.png](../assets/images/validator/def7de0cd1994f64a9da55b5ab7f2993.png) 

To confirm that this is actually the correct flag let's disassemble the file.

When we disassemble the `main` function in `radare2` we are able to see values being moved into different `vars`. These values look like the characters we saw from the `strings` command earlier.

![flag_string.png](../assets/images/validator/bbc9e91895b5476fa7d6c5435ab163f4.png)

To confirm that this is infact the correct flag we can enter a dummy string and compare our input with `var_38h`. We need to make sure that our string is 43 characters so that we can pass the string length comparison at `0x0804858a`. 

![strcmp.png](../assets/images/validator/11014eebb6d94dcd86164c360fdd95fe.png)

To generate the string quickly we can use this oneliner `''.join(random.choices(string.ascii_uppercase + string.digits, k=43))` 

![python.png](../assets/images/validator/9f102042249e4ba9a134eb8cb16745be.png)

We will also need to set a breakpoint at `0x080485ba`. This is where `eax` is being pushed to the string compare after receiving the address of the flag string. 

When we hit our breakpoint, `eax` contains the address `0xffda8060`.

![registers.png](../assets/images/validator/8b7718e089f3439d953c331d90151577.png)

When we view the contents stored at the address we get the flag.

![flag.png](../assets/images/validator/b31945b260df407995827ad7f5d2d699.png)

When we enter in the flag as a solution we get `Valid flag`.

![solution.png](../assets/images/validator/8038967ca8da4074821e9b132430051b.png)