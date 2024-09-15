---
title: "Level Keygen - Crackmes One"
date: 2024-09-15 08:00:00 - 0500
categories: [Crackmes, Unix/linux etc.]
tags: [Crackmes, Reverse, C/C++, Linux, GDB, Ghidra]
image: 
  path: /assets/img/posts/crackme/levelkeygen/Levelkeygen.jpg
---

**Description:** Lots of puts and printf... for people who want a way to progress from level 1 to level 2 and better understand there decompiler framework. If you want the original source code i mightt post it in a day or 2. You are restricted from patching until the bonus stage.

![Level Keygen](/assets/img/posts/crackme/levelkeygen/banner.png){: width="972" height="589" }

## Checking the file
Hello you guys, welcome back to another challenge with n00b in cybersecurity. Today, I'll be presenting one of the crackme challenges called `Level Keygen`.

```bash
$ file LevelsByMacaroni841  

LevelsByMacaroni841: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e7e1ccd9e8817a0184ad4cfd39ed300a5d8f7d94, for GNU/Linux 3.2.0, not stripped
```
{: .nolineno }

## Debuging with GDB

Since this program is not stripped, I can use a debugger tool to examine and step through its code. 

First, I used the `info func` command to check what functions are in this program.

![infofunc](/assets/img/posts/crackme/levelkeygen/infofunc.png){: width="972" height="589" }

Let's look at the first lines of the main function. In this code, it sets up the stack frame, prepares parameters for the `printf` function, and calls `printf`, which will print the string `'Enter a string: '`

```
   0x00000000000011c9 <+0>:	endbr64
   0x00000000000011cd <+4>:	push   rbp
   0x00000000000011ce <+5>:	mov    rbp,rsp
   0x00000000000011d1 <+8>:	sub    rsp,0x70
   0x00000000000011d5 <+12>:	lea    rax,[rip+0xe2c]        # 0x2008
   0x00000000000011dc <+19>:	mov    rdi,rax
   0x00000000000011df <+22>:	mov    eax,0x0
   0x00000000000011e4 <+27>:	call   0x10b0 <printf@plt>
```
{: .nolineno }

![first lines of main function](/assets/img/posts/crackme/levelkeygen/firstlinesofmain.png){: width="972" height="589" }

Next, it loads the address of the fgets function from libc, executes the fgets call to get the input, and stores it in the memory location [rbp-0x40]. Here, fgets will read up to 40 (0x28) characters.

```
   0x00000000000011e9 <+32>:	mov    rdx,QWORD PTR [rip+0x2e20]        # 0x4010 <stdin@GLIBC_2.2.5>
   0x00000000000011f0 <+39>:	lea    rax,[rbp-0x40]
   0x00000000000011f4 <+43>:	mov    esi,0x28
   0x00000000000011f9 <+48>:	mov    rdi,rax
   0x00000000000011fc <+51>:	call   0x10c0 <fgets@plt>
```
{: .nolineno }

At this point, I entered a string. This string is stored at `[rbp-0x40]`, so when I use the `x/s` command, it'll display the string I entered. 

![entered the string](/assets/img/posts/crackme/levelkeygen/enteredstring.png){: width="972" height="589" }

Next, the program will call the strlen function to calculate the length of the string you entered.

![cal len of string](assets/img/posts/crackme/levelkeygen/cal-len-string.png){: width="972" height="589" }

The value returned by the strlen function is stored in the `rax` register. The length of the string you entered is 8, and this includes the newline character (`\n`) that is added when you press Enter.

![len](/assets/img/posts/crackme/levelkeygen/len.png){: width="972" height="589" }

After getting the string length, the program calls cmp to compare the length with 6. If the length is not equal to 6, it jumps to the address `main+589` and prints the string `"FAILURE-LVL-1: how long is your string? Do you know what a NULL terminator is?"`

![Compare string len](/assets/img/posts/crackme/levelkeygen/cmp.png){: width="972" height="589" }

To pass level 1, the input string must be exactly 5 characters long.

![](/assets/img/posts/crackme/levelkeygen/passl1.png){: width="972" height="589" }

In this step, I need to change the value of $rax in order to bypass the cmp instruction. `set $rax=0x6`

The message 'Level 1 Pass: String length is correct' will be printed if we enter a string with the correct length, specifically 6 characters.

![](/assets/img/posts/crackme/levelkeygen/lv1pass.png){: width="972" height="589" }

Next, it will take one byte from the memory location `[rbp-0x3f]` and compare it with the value `0x34`.

![](/assets/img/posts/crackme/levelkeygen/comparewith0x34.png){: width="972" height="589" }

As analyzed above, the string we input is stored at `[rbp-0x40]`, so the location `[rbp-0x3f]` is actually the first byte of the string we entered.

Next, set the value of `$rax` to `0x34` in order to pass the cmp instruction.

![](/assets/img/posts/crackme/levelkeygen/setrax0x34.png){: width="972" height="589" }


Next, compare whether the value of the byte at position 0 is equal to 0x33.

![](/assets/img/posts/crackme/levelkeygen/comparewith0x33.png){: width="972" height="589" }

Okay, so you've passed level 2.5. Next, the following string will be printed: 'You will be prompted to enter a second key..... I know. Annoyyyingggg.'

![](/assets/img/posts/crackme/levelkeygen/image1.png){: width="972" height="589" }

Next, enter the second string. Similar to the first string, after entering it, the length of the string is checked and compared with the value at `[rbp-8]`, which is the length of the first string. Thus, the second string must also be 6 characters long, and the string you enter is stored at `[rbp-0x70]`.

![](/assets/img/posts/crackme/levelkeygen/image2.png){: width="972" height="589" }

In this section, there is a loop from `[0-4]`  to compare each byte in the two strings. Analyzing this code, you can see that the character in `s2[index] - 0x30` should equal `(s1[index] - 0x30) * 2`. Therefore, you can choose characters starting from 0 onward, because each byte should be subtracted by 0x30 (the position of the character 0 in the ASCII table) to meet the condition. Also, avoid choosing characters from a onward for the first string because selecting such characters for the second string will result in characters in the extended ASCII codes (>127). To simplify, I will choose the remaining 3 characters (since the first 2 characters must be 34) in the first string as 0, so there's no need to think about selecting characters that satisfy the condition for the second string.

![](/assets/img/posts/crackme/levelkeygen/image3.png){: width="972" height="589" }

![](/assets/img/posts/crackme/levelkeygen/image4.png){: width="972" height="589" }

So, we can pass the levels, but there's still one final challenge, here:

![](/assets/img/posts/crackme/levelkeygen/image5.png){: width="972" height="589" }


In this part, scanf is used to input some value, and then it compares the value at `[rbp-8]` with `0x1b39` to determine whether to print the next string.

As analyzed earlier, the value at `[rbp-8]` represents the length of the string we entered, which is 6. Therefore, you need to change the value `0x1b39` to `0x6`.

![](/assets/img/posts/crackme/levelkeygen/image6.png){: width="972" height="589" }

Final.

![](/assets/img/posts/crackme/levelkeygen/image7.png){: width="972" height="589" }


This is a piece of code in the main function decompiled by Ghidra. You can immediately see the flow of the program, but since this is an easy challenge, I want to use GDB to execute it step by step to understand the assembly code as well as how to use GDB for debugging. !Thanks


```c++
undefined8 main(void)

{
  size_t sVar1;
  char local_78 [48];
  char local_48 [52];
  int local_14;
  int local_10;
  int local_c;
  
  printf("Enter a string: ");
  fgets(local_48,0x28,stdin);
  sVar1 = strlen(local_48);
  local_10 = (int)sVar1;
  if (local_10 == 6) {
    puts("\n\n\nLevel 1 Pass: String length is correct\n\n");
    if (local_48[1] == '4') {
      puts("Level 2 Pass: the character is as expectedd\n\n");
      if (local_48[0] == '3') {
        puts("Level 2.5 Pass: You understand the requirement\n\n");
        puts("you will be prompted to enter a second key..... I know. Annnnoyyyingggg");
        puts(
            "The first key and the second key have a certain relationship figure this out to pass\n\ n"
            );
        printf("Enter string #2: ");
        fgets(local_78,0x28,stdin);
        sVar1 = strlen(local_78);
        local_14 = (int)sVar1;
        if (local_14 == local_10) {
          for (local_c = 0; local_c < 5; local_c = local_c + 1) {
            if (local_78[local_c] + -0x30 != (local_48[local_c] + -0x30) * 2) {
              puts(
                  "FAILURE-LVL-2-Look through the logic in a ghidra or something Im sure youll under stand it then"
                  );
              break;
            }
          }
          puts("SUCCESS-LVL-3: You Did it! i hope you learned something.\n\n");
          puts(
              "**i pray for the day crackmes.one adds a section for hints that the author can add**\ n"
              );
          puts(
              "If you havent done it before this will be a little bonus section for binary patching"
              );
          puts(
              "For the bonus section you need to modify the binary to bypass an impossible if statem ent"
              );
          puts("When ready type a letter then press enter to go into the statement: ");
          __isoc99_scanf(&DAT_00102365);
          if (local_10 == 6) {
            puts("SUCCESS-LVL-BONUS: Well damn you did it");
            puts("Should I make more of these?");
            puts(
                "Probably not with the yanderedev if statement spam and 7 million calls to printf, b ut ill work on it"
                );
            puts("Bye! - saltedMacaroni841");
          }
          else {
            puts("FAILURE-LVL-BONUS: Forcing you to type all that crap again i know.. cruel");
            puts("Cutter is actually pretty good for this");
            puts("Wowza! https://www.megabeets.net/5-ways-to-patch-binaries-with-cutter/");
          }
        }
        else {
          puts("The string length has to be the same");
        }
      }
      else {
        puts("I think if requires another character in another certain position?");
      }
    }
    else {
      puts(
          "FAILURE-LVL-2: Maybe the program wants a certain character in a certain position to proce ed?\n\n"
          );
    }
  }
  else {
    puts("FAILURE-LVL-1: how long is your string? Do you know what a NULL terminator is?.");
  }
  return 0;
}
```
{: .nolineno }

Done!