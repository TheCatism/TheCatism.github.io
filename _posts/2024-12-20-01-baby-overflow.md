---
title: "Seal's Pwn Zero2Hero Stack Challenges - Baby Overflow" 
date: 2024-12-20
classes: wide
categories:
 - pwn
 - Seal's Pwn Zero2Hero Stack Challenges
 - ctf
 
tags:
 - pwn
 - ctf
---


This challenge was found [here](https://github.com/seal9055/PWN_Zero2Hero/tree/main)

* * *

## Vulnerability

The source was provided for this challenge

![source_file.png](../assets/images/baby_overflow/a26ef839dde08728bfa6c8775592890f.png)

The vulnerablitiy can be seen on `line 36`. The fgets call is set to read 0x10 bytes (16 in decimal) instead of just 10 bytes which is the size of our buffer. This gives us 6 extra bytes that we can write onto the stack.

## Exploitation

The source file shows that there is an input check that needs to be met before the flag can be read.

![input_check.png](../assets/images/baby_overflow/785d243dbe36fdec40f40ef9a5fe3c63.png)

If the check isn't met then the program will just print `I guess u just aren't good enough yet. ¯\\_(ツ)_/¯`

To bypass this check we first need to make sure that `-good-` is a part of our input. This ensures that `good` gets tokenized.

After that we need to send `0xdeadbeef` at the end of our input to change the value of password and bypass the second check.

When you open the binary in ghidra you can see that the extra 6 bytes of data we overflow pours in to the password variable that gets checked. This happens because the password variable (local_14) is placed after our buffer (local_1e) on the stack.

![ghidra.png](../assets/images/baby_overflow/9dbacdaba103a833d330c4cd0f0b0e4c.png)

We can use pwntools to interact with the program and send our input. 

Our input will look like this `-good-AAAA\xef\xbe\xad\xde`. it starts off by tokenizing good and then sending `4 A's` to fill the rest of the buffer. `0xdeadbeef` is then added at the end to bypass the password check. `0xdeadbeef` is backwards due to the program being little endian.

## Solution

Pwntools solve script is below with the flag

![solve_script.png](../assets/images/baby_overflow/be08646bc16b95f54121a7f75f1fbae9.png)

![flag.png](../assets/images/baby_overflow/a1ff36978a6f05de9c17a5f59bc9e7ef.png)