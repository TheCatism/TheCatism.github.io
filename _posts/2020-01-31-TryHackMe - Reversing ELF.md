---

title: "TryHackMe - Reversing ELF"  
date: 2021-01-31  
classes: wide 
header:
 teaser: ../assets/images/reversing_elf/6ed92562e36244519aee066a548811ff.png)
 teaser_home_page: true
categories:
 - reverse engineering
 - infosec
 - crackme
 - tryhackme

tags:
 - reverse engineering
 - crackme
 - ghidra
 - radare2
 - tryhackme

---





![09e72853db5f1a9dd0bff63325acd99e.png](../reversing_elf/81d4fc30fc094d4e9f2caf2a5492f7b3.png)

`Reversing Elf` is a TryHackMe challenge that lets you look for flags in 8 Crackme files.



# Tools Used

## Radare2

[Radare2](https://github.com/radareorg/radare2) is an open source command-line reverse engineering tool. It lets you disassemble and debug programs.

## Ghidra

[Ghidra](https://ghidra-sre.org/) is a reverse engineering tool that was developed by the NSA. The tool allows you to disassemble and decompile binaries, as well as other RE operations.

# Crackme1

**Task 1:** Let's start with a basic warmup, can you run the binary?

* * *

When we run the `file` command it tells us that this is a 64 bit elf file.

![file_command.png](../reversing_elf/6fbd650e6650481ba3dee59194599e51.png)

The challenge says "Let's start with a basic warm up, can you run the binary?".  
This pretty much tells us that we just need to run the file to get a flag.

By giving the crackme1 file execution rights we can run it and get the flag.

![running_the_file.png](../reversing_elf/2ebf5423496f4f2a9fe48c12f9f8976b.png)

# Crackme2

**Task 2:** Find the super-secret password! and use it to obtain the flag

* * *

This challenge has two parts. The first part is to find the password and the second part is to use the password we found to get a flag.

Running the `file` command tells us that this is a 32 bit elf file.

![crackme2_file.png](../reversing_elf/fa06de3524f14d0e8c1e851e89261165.png)

By using the `strings` command we can check to see if there are any hard coded passwords.

When we check we find the string `super_secret_password`

We can also see the program's usage message which tells us to run it with what we think is the password.

![strings.png](../reversing_elf/9a53cc4db52c4955bf4206aaefc4d255.png)

When running the program with the string `super_secret_password` we receive the access granted message and our flag.

![crackme2_flag.png](../reversing_elf/d5bca297d90f4565bdca86ac138758d0.png)

# Crackme3

**Task 3:** Use basic reverse engineering skills to obtain the flag

* * *

This challenge tells us to use basic reverse engineering skills to obtain the flag.

The `file` command tells us that this is a 32 bit elf file.

![file_crackme3.png](../reversing_elf/d876005d69c84d1d9aaadf8695e64084.png)

The `strings` command shows us that there is a base64 encoded string.

![strings_crackme3.png](../reversing_elf/63eb348cd7b64643a53dcd4a63064145.png)

Decoding the string gives us our flag.

![crackme3_flag.png](../reversing_elf/fa39b6e31c7142d791ae8e492feff062.png)

Running the program and using the flag as the password will also display the correct password message.

![correct_password.png](../reversing_elf/8eae6e3a7a9b451c87cc3fbb17b1c2e6.png)

# Crackme4

**Task 4:** Analyze and find the password for the binary?

* * *

This challenge tells us to analyze it and find the password.

Running the `file` command tells us that this a 64 bit elf file.

![crackme4_file.png](../reversing_elf/c3a57a599aa04931969cdbcb7e042dec.png)

`strings` tells us that the program hid the string and used the string compare function.

![strings_crackme4.png](../reversing_elf/0e9f222922e94110aff1a6c567496c6d.png)

Since we can't see any hard coded passwords we will use a debugger and analyze the binary.

The debugger I will use is `radare2`.

To debug a file with `radare2` you need to run this command: `r2 -d ./crackme4 <password_arguement>`.

![run_with_pass.png](../reversing_elf/e87cafc0696541f79898a7b0ef96b319.png)

To analyze the file type `aa`. This tells the debugger to analyze all the flags. After the analysis is complete you can type `afl`. This will list all of the functions used by this program. If there's a lot you can pipe the output to grep and search for the main `afl | grep main`.

![analysis1.png](../reversing_elf/d80497913fe3459999e1697c5412a4c6.png)

To disassemble a function like the main function, for example, run `pdf @main`

![disass_main.png](../reversing_elf/6ddaf3becd8a4957ac604c66d835587d.png)

Looking at the main we can see that the program first checks that the correct amount of arguments was passed into the program.

![arg_check.png](../reversing_elf/7f1b3efe46a84b86a7713305ffb56294.png)

The program does a comparison to check that the right amount of arguments was provided. If the right amount was given the program jumps to the memory address located at `0x400746`. Otherwise, the program prints the usage menu. We can also see that our input is stored in the variable `var_10h`

Since we know that we passed a password when we started `radare2` we can follow the jump.

The jump takes us to a section of the main where the program calls a `compare_pwd` function.

![calling_str_compare.png](../reversing_elf/9644536c11624864810ca5361f30e0f6.png)

Since we know that the program is comparing our input to the correct password, we can dissassemble the `compare_pwd` function and look for where the program does this comparison.

If we set our breakpoints correctly we should be able to print out the password before the program finishes and tells us that our input is wrong.

To dissassemble the `compare_pwd` function, we need to type `pdf @sym.compare_pwd`. This will give us the output shown below.

![dissass_cmp_pw.png](../reversing_elf/859e9e507d5c4168ac38c29160b2849f.png)

The function takes in one paramenter, which is the input that we provided. It then calls a get_pwd function and passes the variable `var_20h` as a parameter.

![analysis1_str_cmp.png](../reversing_elf/5e8b6f0d09dd401d92ba1b08f677287a.png)

Based on the name of the function we can assume that this function is used to get the correct password.

After the program gets the correct password it then compares our input to the output of `get_pwd`. If the password is correct it will print out a password OK message otherwise it will print a password not OK message.

![rest_of_str_smp.png](../reversing_elf/a76f7317358546caa7a86822e0a5d605.png)

If we set a breakpoint after the `get_pwd` is called but before the `strcmp` function is called we should be able to print out what was returned by the `get_pwd` function.

![breakpoint.png](../reversing_elf/a2867789c268494485bfdd826f6925c5.png)

By setting a breakpoint at the address of `0x004006cf` we are able to print the contents of the variable `var_20h`, the variable that was passed into `get_pwd`.

To set a breakpoint type `db <memory_address>` and then type `dc` to run the program until you hit that breakpoint.

To print the contents of `var_20h` type `px @ rbp-0x20`. The `rbp-0x20` is the location that the `var_20h` variable is stored at.

![printing_pwd.png](../reversing_elf/f9cff26b291543b3af41fe032485dbf2.png)  
Looking at the hex dump we can see that the password is `my_m0r3_secur3_pwd`

Running the program with this password gives us the Password OK message.

![password_ok.png](../reversing_elf/538e273b6e3c4e3493bb3c4b4e77398b.png)

# Crackme5

**Task 5:** What will be the input of the file to get output `Good game`?

* * *

The challenge tells to find the input needed to get the output Good game.

Running the `file` command tells us that this a 64 bit elf file.

![file_crackme5.png](../reversing_elf/ea5c6548b7a74834bffee06f244ee7fb.png)

The `strings` command shows us that the program prompts for input and then depending on the input will either display the message `Good game` or `Always dig deeper`

![strings_crackme5.png](../reversing_elf/02b11f5522c24491a0235188ca60d5ed.png)

Similarly to how we did Crackme4, let's start up `radare2` and analyze the file.

![loading_up_file.png](../reversing_elf/bf348d1d247f4af5bf379a1d84bcdc92.png)

First thing we can notice when dissembling the main function is that there are a lot variables.

![main_p1.png](../reversing_elf/878e60593f3c4a65a31a923f840c7ae9.png)

Scolling down some more we can see that before we are prompted for input, a lot of these variables are being set to a character. This is probably the string that we need to input in order to get the `Good game` message but let's analyze some more and confirm our hunch.

![main_p2.png](../reversing_elf/04bf3ecd94544c2ca74917999ff2bc36.png)

The rest of the main function shows that our input is taken in at memory address `0x0040081c`. We can also see that the program calls the `strcmp` function at `0x0040082f`.

The program later does another comparison. If this comparison is equal the program prints the `Good game` message, otherwise the `Always dig deeper message` will be displayed.

![main_p3.png](../reversing_elf/b96a3ffd22844e63abcbe7778609f451.png)  

Similarly to how we found the password in crackme4, if we set a breakpoint somewhere between where the program takes in our input and where the string comparison is made, we should be able to print the string that our input is being compared to.

By setting a breakpoint at `0x00400829`, we are able to print both our input string and the comparison string which were stored at `var_50h` and `var_30h`

![flag.png](../reversing_elf/ec8b179e9902426faa61e7fa39cd0c4b.png)

Looking at the output we see that our earlier hunch about the variables that were listed above was correct.

By using the string that was stored at `var_30h` we are able to get the `Good game` message.

![correct_output.png](../reversing_elf/a39e4f9a5f314171bb8306406d264d72.png)

# Crackme6

**Task 6:** Analyze the binary for the easy password

* * *

Challenge tells us to analyze the binary and to look for the easy password.

The `file` command tells us that this is a 64 bit elf file.

![file_crackme6.png](../reversing_elf/f257fa3a2faf4594985491fb4acb237f.png)

The `strings` command shows us that the program looks for a password and that if the password is correct it will print password OK, on the other hand if the password is wrong it will print password not OK.  
![strings_crackme6.png](../reversing_elf/5461d10853ce490d8486cc6f71db8542.png)

The usage menu tells us to read the source. This could be a hint telling us to use a decompiler.

![usage_message.png](../reversing_elf/e5fca33bd484439887f5fed20dfdc9f1.png)  

Following the hint we can use ghidra as a decompiler.  

If you haven't used ghidra before you can start getting familiar with it by visiting `https://ghidra-sre.org/`

After analyzing the binary with ghidra we're able to see the source code.

Going to the main function we can see that it calls a `compare_pwd` function.

![ghidra_main_func.png](../reversing_elf/8e694bd646f14eaa8e0e1d068f146452.png)

Looking at the `compare_pwd()` we see that it is calling another function called `my_secure_test()`. It stores the value that is returned by `my_secure_test()` in the `uVar1` variable. It then checks that `uVar1` equals 0. If it does then it prints then the password ok message, if it does not it prints the password not ok message.

![compare_pwd.png](../reversing_elf/e1d132d5aa4544a4a1e5e961180a4f27.png)

`my_secure_test()` is a series of nested if statements that checks for the correct password character by character. If all the characters match the function sets `uVar1`to 0 otherwise `uVar1` is set to `0xffffffff`.

By looking at the characters that are being compared we can see the correct password is `1337_pwd`

![my_secure_test.png](../reversing_elf/fcaa0f3df7524e7a9dc5e1f6b441dc27.png)

Using the password we found gives us the password ok message.

![flag_crackme6.png](../reversing_elf/58b2f144f0e84173a4a5714032c5adb7.png)

# Crackme7

**Task 7:** Analyze the binary to get the flag

* * *

The challenge tells us to analyze the binary and to get the flag.

The `file` command shows that this is a 32 bit elf file

![file_crackme7.png](../reversing_elf/97365d0427924e258cc722283cc60582.png)

The `strings` command shows us that this is a program that contains a menu with two options.

![strings_crackme7.png](../reversing_elf/27c216a2e9bb4479976c4a7909e0cec3.png)  

The first option is to give the program a your name which is echoed back. The second option is to give it two numbers to add up.

This can be confirmed when we run the program.

![init_run.png](../reversing_elf/27b1787b20c547e5a95ffe106a17a38b.png)

Loading the program the program into `radare2` we see lots of jumps being called.

![main1.png](../reversing_elf/748fb50e57f24f8b8fd2f1c9641f2084.png)

![main2.png](../reversing_elf/b6176bf62dc549dcaaca4a9ac5b9e1fe.png)

This means that there's loops and conditionals being used within the program.

While scanning through the main function the first thing that catches my eye is `0x08048665`.

![1337.png](../reversing_elf/51ed6abcfeb24086ba4b1b177a61b16c.png)

`0x08048665` shows that the program compares `eax` with `0x7a69`, which is `31337` in decimal. If the two values are equal it will print out the `Wow such h4x0r!` message and give us our flag.

To see where we need to input the `31337` we can decompile the program and look at the main function.

![decompiled.png](../reversing_elf/206fc02539814fe7a0b7979cd23924fd.png)

Looking at `line 20` we can see that our input is stored in the variable local_14.

Scanning down the main we see that at `line 41` there's an if statement for if our input is not equal to two.

![flag1.png](../reversing_elf/640326a9be394a9f84e80b54e3b42403.png)

If our input is three we get the goodbye message but if our input equals `0x7a69` (the hex number we saw in radare2) in decimal format, we get the flag.

When input the number into the program we get our flag.

![flag2.png](../reversing_elf/409368996db74f0ea4b09d7b6b291445.png)

# Crackme8

**Task 8:** Analyze the binary and obtain the flag

* * *

The challenge tells us to analyze the binary and to get the flag.

The `file` command shows that this is a 32 bit elf file

![file_crackme8.png](../reversing_elf/bbfb96197289463abbf6cb97e8f02cb0.png)

The `strings` command shows us that there aren't any hard coded passwords.

![strings_crackme8.png](../reversing_elf/d4bea340159a457fb433af40be6afe47.png)

Running the program without a password arguement makes the program print out a usage message.

If we put in the wrong password then we get Access denied.

![usage.png](../reversing_elf/99584a6105004246b4266d4d29713211.png)

Disassembling the main with `radare2` shows us that there is a comparison at `0x080484e4`

![main_radare.png](../reversing_elf/f6efd09cf8cf4304a65c8c847153b860.png)

The program is comparing the `eax` register with the hex of `0xcafef00d`. If the two are equal the program prints the flag.

Converting the hex to decimal gives us `3405705229` as the decimal number and `-889262067` as the signed two's compliment.

To get the flag we can either try both numbers or confirm which one we need by decompiling the program.

![converted.png](../reversing_elf/9fccb566e0ef4adc89e4bd82815d749f.png)

Using ghidra we can decompile the program to see what we need to provide as input in order for us to get the flag.

![decompiled.png](../reversing_elf/00c54f4402e44f1481658c2ff8031081.png)

Looking at the main function shows us that at `line 10` the program is comparing our string to `-0x35010ff3`. Converting the hex to decimal tells us which number the program is looking for.

![signed_convert.png](../reversing_elf/76326a0dc5c94d7482fb4e13acad90bd.png)

Putting the `-889262067` as an arguement for the program gives our flag.

![flag_crackme8.png](../reversing_elf/7b534059c00f4875b8a7f9c57a4991ac.png)