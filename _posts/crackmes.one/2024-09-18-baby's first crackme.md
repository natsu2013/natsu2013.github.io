---
title: "baby's first crackme - Crackmes One"
date: 2024-09-19 08:00:00 - 0500
categories: [Crackmes, Unix/linux etc.]
tags: [Crackmes, Reverse, C/C++, Linux, GDB, Ghidra]
image: 
  path: /assets/img/posts/crackme/baby's first crackme/banner.png
---

**Description:** I made it with a certain password (you would know it if you get it), but there are many passwords that work

![Baby's first crackme](/assets/img/posts/crackme/baby's first crackme/image1.png){: width="972" height="589" }

## Check file
Similar to other challenges, for this challenge, I was also provided with a zip file. Unzip this file reveals an executable named `rust_1`.

## Analysis

Open this file with GDB for debugging and we can see the programs have functions such as: `main`, `check_key`, and `encode_input`.

![image](/assets/img/posts/crackme/baby's first crackme/image.png){: width="972" height="589" }

This code sets up stack frame: `sub rsp, 0x20` -> decreases the value of `$rsp` by 32 bytes to allocate space for the local variables of the function.

Take the values of the register `eid` and `rsi` and assign them to the memory locations `[rbp-0x14]` and `[rbp-0x20]`, respectively.

Next, compare the value at `[rbp-0x14]` (which holds the value of `edi`, typically the first parameter, `argc` from the main function) with `0x2`.
```
  0x00000000000013b8 <+0>:	endbr64
  0x00000000000013bc <+4>:	push   rbp
  0x00000000000013bd <+5>:	mov    rbp,rsp
  0x00000000000013c0 <+8>:	sub    rsp,0x20
  0x00000000000013c4 <+12>:	mov    DWORD PTR [rbp-0x14],edi
  0x00000000000013c7 <+15>:	mov    QWORD PTR [rbp-0x20],rsi
  0x00000000000013cb <+19>:	cmp    DWORD PTR [rbp-0x14],0x2
  0x00000000000013cf <+23>:	jg     0x13ea <main+50>
```
{: .nolineno }

So, when running the program, at least two parameters must be provided; otherwise, it will jump to the code below. 

In this code segment, it'll call the `put` function to print a string located at `[rip+0xc50]`, and return.

![image](/assets/img/posts/crackme/baby's first crackme/image2.png){: width="972" height="589" }

Therefore, to run this program, I need to provide two input parameters: `key` and `number`.

In the next code segment, the program retrieves the values of `key` and `number`. 

As we analyze, the parameter `char** argv` of the main function is stored at `[rbp-0x20]`, which points to `0x7fffffffdc50`. This address contains the value `0x7fffffffdd88` -> `0x7fffffffe126` (the path of the program).

The value at `$rax + 8` equals `0x7fffffffdd88 + 8 = 0x7fffffffdd90`, where `0x7fffffffdd90` holds the value `0x7fffffffe14f`, pointing to the key string we provided, or `argv[1]`.

Similarly, the position at `[rbp-0x20] + 0x10` corresponds to `argv[2]`, which is the number.

The program then calls the `atoi` function to convert the number from a string to an integer.

![image](/assets/img/posts/crackme/baby's first crackme/image3.png){: width="972" height="589" }

Next, the program calls the `strlen` function to calculate the length of the `key` string and compares it with `0xc`. If they are equal, it jumps to `main+129`. 

![image](/assets/img/posts/crackme/baby's first crackme/image4.png){: width="972" height="589" }

In this segment, the program checks if the value of `number` is greater than 0 and less than `0x32` (50).

The `js` instruction is conditional jump that will jump to a specified address if the sign flag (SF) in the EFLAGS register is set. The SF flag is set by arithmetic instruction, such as `sub`, when the result is a negative number. 

![image](/assets/img/posts/crackme/baby's first crackme/image5.png){: width="972" height="589" }

The `strcspn` function finds the first occurrence of any character in `key` that is not a newline character `\n`. 

![image](/assets/img/posts/crackme/baby's first crackme/image6.png){: width="972" height="589" }

After finding the first position in `key` that does not contain a newline character (`\n`), the program will assign a null terminator (`\0`) at that position. At this point, the values of key and number are passed as parameters to the `check_key` function.

![image](/assets/img/posts/crackme/baby's first crackme/image7.png){: width="972" height="589" }

At this point, I'm quite lazy to analyze the assembly, so let's switch to analyzing the pseudocode in Ghidra for a quicker understanding.

In the `check_key` function, it can be seen that the `encode_input` function is called with three parameters: `param_1`, `param_2`, and `local_58`. The `encode_input` function performs some calculations and stores the returned result in `local_58`.

Next is an infinite while loop that iterates through the characters in `local_58` and stores the last character in `local_64`.

An if statement checks if the value of the variable `local_64` is equal to `0x7c` (which is the pipe character `|`). If true, it prints "`Access granted`"; otherwise, it prints "`Access denied!`".

```c
void check_key(undefined8 param_1,undefined4 param_2)

{
  size_t sVar1;
  long in_FS_OFFSET;
  int local_64;
  int local_60;
  char local_58 [56];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  encode_input(param_1,param_2,local_58);
  local_60 = 0;
  while( true ) {
    sVar1 = strlen(local_58);
    if (sVar1 <= (ulong)(long)local_60) break;
    local_64 = (int)local_58[local_60];
    local_60 = local_60 + 1;
  }
  if (local_64 == 0x7c) {
    puts("Access granted!");
  }
  else {
    puts("Access denied!");
  }
  if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
{: .nolineno }


As analyzed in the `check_key` function, we can pass any values for the parameters key and number as long as they meet the following criteria:

- The key has a length of 12 characters.
- The number is within the range (0-50].
- The last character of the result returned by the encode_input function must be `|`.


After understanding the operation of the check_key function, I will look at the encode_input function to see how it works.

This function operates as follows:

- It iterates through the key string until it encounters a null character (`\0`).
- It checks whether the index of that character in the key string is even or odd.
- It then checks the character's ASCII value to determine if it is even or odd, performing corresponding calculations.

```c
void encode_input(long param_1,char param_2,long param_3)

{
  uint local_c;
  
  for (local_c = 0; *(char *)(param_1 + (int)local_c) != '\0'; local_c = local_c + 1) {
    if ((local_c & 1) == 0) {
      if ((*(byte *)(param_1 + (int)local_c) & 1) == 0) {
        *(char *)(param_3 + (int)local_c) = *(char *)(param_1 + (int)local_c) - param_2;
      }
      else {
        *(char *)(param_3 + (int)local_c) = *(char *)(param_1 + (int)local_c) + param_2;
      }
    }
    else if ((*(byte *)(param_1 + (int)local_c) & 1) == 0) {
      *(char *)(param_3 + (int)local_c) = *(char *)(param_1 + (int)local_c) + param_2 * '\x02';
    }
    else {
      *(char *)(param_3 + (int)local_c) = *(char *)(param_1 + (int)local_c) + param_2 * -2;
    }
  }
  *(undefined *)(param_3 + (int)local_c) = 0;
  return;
}     
```
{: .nolineno }

```python 
def encode_input (key: str, num: int) -> str:
    buffer = []
    for local_c in range(len(key)):
        if (local_c & 1) == 0: 
            if (ord(key[local_c])&1) == 0: 
                buffer.append(chr(ord(key[local_c]) - num))
            else: 
                buffer.append(chr(ord(key[local_c]) + num))
        else: 
            if (ord(key[local_c]) & 1) == 0:
                buffer.append(chr(ord(key[local_c]) + num * 0x2))
            else:
                buffer.append(chr(ord(key[local_c]) + num * (-0x2)))
                
    return ''.join(buffer)

```
{: .nolineno }


This task is quite easy; there's no need to overthink it and make it complicated. The only thing to pay attention to is ensuring that the last character in the key (the 11th character) encodes to the pipe character `|`, and that this character is either even or odd in decimal form. The other characters can be anything, as long as they are not special characters.

Okay, so I have a snippet of code that generates valid key and number inputs. However, it needs to exclude any special characters. !Thanks

```python
def get_key_num():
    key = 11 * 'x'
    for i in range (15,128):
        if i & 1 == 0:
            num = (0x7c-i)//2
            if num > 0 and num < 0x32: 
                print('{}{} - {}'.format(key, chr(i), num))
        else: 
            num = (i-0x7c)//2
            if num > 0 and num < 0x32: 
                print('{}{} - {}'.format(key, chr(i), num))
```
{: .nolineno }

At this point, we can conclude the challenge. However, I just remembered a case: if I run the program like this `./rust_1 zzzz\nzzzzzzz 2`, this string for key and number is correct, and the program prints "`Access granted`"

However, the key string contains the `\n` character, so why does it still work according to the principle I mentioned, where only the last character in the key and the number need to encode to `|`?

The reason for this is that the shell (bash or zsh) does not interpret `\n` as a newline here; instead, it understands `\` as an escape character. Since n is not a special character, it remains unescaped, resulting in the input string being `zzzznzzzzzzz`.

That's on!



