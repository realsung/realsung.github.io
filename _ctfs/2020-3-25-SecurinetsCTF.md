---
title: "2020 Securinets CTF Quals"
date: 2020-3-18
ctf: Securinets CTF
layout: post
---

# Forensic

## Time matters

내가 푸는 방법이 맞았는데 오류떠서 그냥 포기했는데 오류 해결했으면 풀었을텐데 아쉬웠다. mimikatz를 이용하는 방법이다. 예전에 내가 사용한 적이 있었다.

shellbag을 확인해보면 Desktop에 steghide, DS0394.jpg에 접근했었다. 

```
Scanning for registries....
Gathering shellbag items and building path tree...
***************************************************************************
Registry: \??\C:\Users\studio\ntuser.dat 
Key: Software\Microsoft\Windows\Shell\Bags\1\Desktop
Last updated: 2020-03-20 12:37:38 UTC+0000
Value                     File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Unicode Name
------------------------- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ------------
ItemPos1920x1005x96(1)    GOOGLE~1.LNK   2020-03-20 12:19:22 UTC+0000   2020-03-20 12:19:22 UTC+0000   2020-03-20 12:19:22 UTC+0000   ARC                       Google Chrome.lnk 
ItemPos1920x1005x96(1)    steghide       2020-03-20 12:35:02 UTC+0000   2020-03-20 12:35:02 UTC+0000   2020-03-20 12:35:02 UTC+0000   DIR                       steghide 
ItemPos1920x1005x96(1)    DS0394.jpg     2020-03-20 12:33:36 UTC+0000   2020-03-20 12:33:36 UTC+0000   2020-03-20 12:33:36 UTC+0000   ARC                       DS0394.jpg 
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\studio\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU
Last updated: 2020-03-20 12:35:17 UTC+0000
Value   Mru   Entry Type     GUID                                     GUID Description     Folder IDs
------- ----- -------------- ---------------------------------------- -------------------- ----------
1       1     Folder Entry   59031a47-3f72-44a7-89c5-5595fe6b30ee     Users                EXPLORER, USERS 
0       2     Folder Entry   031e4825-7b94-4dc3-b131-e946b44c8dd5     Libraries            EXPLORER, LIBRARIES 

Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
2       0     steghide       2020-03-20 12:35:02 UTC+0000   2020-03-20 12:35:02 UTC+0000   2020-03-20 12:35:02 UTC+0000   DIR                       steghide
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\studio\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1
Last updated: 2020-03-20 12:34:56 UTC+0000
Value   Mru   Entry Type     GUID                                     GUID Description     Folder IDs
------- ----- -------------- ---------------------------------------- -------------------- ----------
0       0     Folder         374de290-123f-4565-9164-39c4925e467b     Downloads            EXPLORER 
***************************************************************************

***************************************************************************
Registry: \??\C:\Users\studio\AppData\Local\Microsoft\Windows\UsrClass.dat 
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\0
Last updated: 2020-03-20 12:34:56 UTC+0000
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----
0       0     steghide-0.5.1-win32.zip 1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   1970-01-01 00:00:00 UTC+0000   ARC                       steghide-0.5.1-win32.zip
***************************************************************************
```

대충 steghide로 파일을 DS0394.jpg에 숨겨놨을 것이다. 근데 비밀번호를 알아야한다. 

hashdump를 하면 아래 같이 뜨는데 studio 비밀번호를 알기위해서 mimikatz를 이용했다. 

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
studio:1001:aad3b435b51404eeaad3b435b51404ee:0bec1e259bd7346e2e2544e1ba9f2054:::
HomeGroupUser$:1002:aad3b435b51404eeaad3b435b51404ee:0a5567be74be28bbe245e025b5b3a757:::
```

```
$ vol.py -f for1.raw --profile=Win7SP1x86 mimikatz
Volatility Foundation Volatility Framework 2.6.1
Module   User             Domain           Password
-------- ---------------- ---------------- ----------------------------------------
wdigest  studio           studio-PC        Messi2020
wdigest  STUDIO-PC$       WORKGROUP
```

그리고 사진에는 2019 써있어서 steghide extrace로  `Messi2019` 입력해주면 flag 적혀있는 image.png 뽑을 수 있다. 

**FLAG : `Securinets{c7e2723752111ed983249627a3d752d6}`**

<br />

## Time Problems

chromehistory를 보게되면 `http://52.205.164.112/` 라는 사이트에 접근한적이 있다 다른 것은 다 neymar에 대해 검색했다. 

timetravel로 검색해보면 http://timetravel.mementoweb.org/list/20190818233503/http://52.205.164.112 archive해둔게 나온다. https://web.archive.org/web/20200318121831/http://52.205.164.112 여기들어가면 네모로 되어있는거 주는데 거기에 neymar 넣으면 된다.

**FLAG : `Securinets{neymar_1s_my_f4vorit3_Pl4yer}`**

<br />

# Reversing

## Warmup : Welcome to securinets CTF

> solve.py

```python
a=[0x46, 0x19, 0x5E, 0x0D, 0x59, 0x75, 0x5D, 0x1E, 0x58, 0x47, 0x75, 0x1B, 0x5E, 0x75, 0x5F, 0x5A, 0x75, 0x48, 0x45, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
print ''.join(chr(i^42) for i in a)
```

**FLAG : `securinets{l3t's_w4rm_1t_up_boy}`**

<br />

## static EYELESS

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  double v3; // xmm3_8
  signed __int64 v4; // ST28_8
  signed __int64 v5; // ST28_8
  signed __int64 v6; // kr00_8
  int i; // [rsp+10h] [rbp-230h]
  signed int j; // [rsp+10h] [rbp-230h]
  int v10; // [rsp+14h] [rbp-22Ch]
  signed __int64 chk; // [rsp+20h] [rbp-220h]
  signed __int64 v12; // [rsp+28h] [rbp-218h]
  int tmp[52]; // [rsp+50h] [rbp-1F0h]
  int v14; // [rsp+120h] [rbp-120h]
  int v15; // [rsp+124h] [rbp-11Ch]
  int v16; // [rsp+128h] [rbp-118h]
  int v17; // [rsp+12Ch] [rbp-114h]
  int v18; // [rsp+130h] [rbp-110h]
  int v19; // [rsp+134h] [rbp-10Ch]
  int v20; // [rsp+138h] [rbp-108h]
  int v21; // [rsp+13Ch] [rbp-104h]
  int v22; // [rsp+140h] [rbp-100h]
  int v23; // [rsp+144h] [rbp-FCh]
  int v24; // [rsp+148h] [rbp-F8h]
  int v25; // [rsp+14Ch] [rbp-F4h]
  int v26; // [rsp+150h] [rbp-F0h]
  int v27; // [rsp+154h] [rbp-ECh]
  int v28; // [rsp+158h] [rbp-E8h]
  int v29; // [rsp+15Ch] [rbp-E4h]
  int v30; // [rsp+160h] [rbp-E0h]
  int v31; // [rsp+164h] [rbp-DCh]
  int v32; // [rsp+168h] [rbp-D8h]
  int v33; // [rsp+16Ch] [rbp-D4h]
  int v34; // [rsp+170h] [rbp-D0h]
  int v35; // [rsp+174h] [rbp-CCh]
  int v36; // [rsp+178h] [rbp-C8h]
  int v37; // [rsp+17Ch] [rbp-C4h]
  int v38; // [rsp+180h] [rbp-C0h]
  int v39; // [rsp+184h] [rbp-BCh]
  int v40; // [rsp+188h] [rbp-B8h]
  int v41; // [rsp+18Ch] [rbp-B4h]
  int v42; // [rsp+190h] [rbp-B0h]
  int v43; // [rsp+194h] [rbp-ACh]
  int v44; // [rsp+198h] [rbp-A8h]
  char passcode[56]; // [rsp+1F0h] [rbp-50h]
  unsigned __int64 v46; // [rsp+228h] [rbp-18h]

  v46 = __readfsqword(0x28u);
  memset(&v14, 0, 0xC8uLL);
  v14 = 209;
  v15 = 30;
  v16 = 219;
  v17 = 251;
  v18 = 116;
  v19 = 203;
  v20 = 21;
  v21 = 221;
  v22 = 250;
  v23 = 117;
  v24 = 217;
  v25 = 75;
  v26 = 218;
  v27 = 232;
  v28 = 115;
  v29 = 209;
  v30 = 79;
  v31 = 204;
  v32 = 231;
  v33 = 54;
  v34 = 204;
  v35 = 78;
  v36 = 231;
  v37 = 252;
  v38 = 54;
  v39 = 193;
  v40 = 16;
  v41 = 141;
  v42 = 175;
  v43 = 123;
  v44 = 168;
  v3 = ret_21();
  v4 = ((v14 * (((30 - 1.0) * ret_251() + 58.0) * v18 + 110) + 141.0) * v3 + 20.0) * (v15 - 20) >> (v15 - 22);
  puts("Hello REVERSER!");
  v5 = 49406 * v4 * (ptrace(0, 0LL, 0LL, 0LL) + 1);// if ptrace ret 1? -> v5 = 0x0000068EB87BA216
  printf("Give me the passcode:");
  v6 = v5;
  v12 = v5 / 256;
  chk = v6 / 256;                               // 0x000000068EB87BA2
  fgets(passcode, 49, stdin);
  v10 = 0;
  for ( i = 0; i < strlen(passcode); ++i )
  {
    if ( !chk )
      chk = v12;
    tmp[i] = chk ^ passcode[i];
    chk >>= 8;
  }
  for ( j = 0; j <= 29; ++j )
    v10 += tmp[j] ^ *(&v14 + j) | 1;
  if ( v10 == -(ptrace(0, 0LL, 0LL, 0LL)
              * (v15 + (1193046 << (v15 - 26) >> (v14 + 72)) - (6636321 << (v15 - 26) >> (v14 + 72)) + 3)) )
    puts("Good job!");
  else
    printf("NOOOOOOOO");
  return 0LL;
}
```

문제 이름부터 static이라니까 정적으로 해야한다. ptrace가 PTRACE_TRACEME라 디버깅모드면 -1리턴해주는데 0으로 덮어주고 들어가는 값만 잘 보면 된다.

> solve.py

```python
chk = 0x000000068EB87BA2
tmp = []
for i in range(100):
	if not chk:
		chk = 0x000000068EB87BA2
	tmp.append(chk & 0xff)
	chk >>= 8

table = [209,30,219,251,116,203,21,221,250,117,217,75,218,232,115,209,79,204,231,54,204,78,231,252,54,193,16,141,175,123,168]
# c = [162, 123, 184, 142, 6] # cycle

flag = ''.join(chr(table[i]^tmp[i%5]) for i in range(len(table)))

print flag
```

**FLAG : `securinets{0bfus4ti0n5_r0ck5!}`**

<br />

## CHANGE

python으로 만든 ELF파일을 준다.

`pyi-archive_viewer` 를 이용해서 파일을 추출해오면 된다. 그리고 pyc코드를 디컴파일하려면 이 파일 맨 앞에 아래 둘 중 하나 추가해주면 된다. 그러면 성공적으로 디컴파일이 된다.

```
03F30D0A 70796930
03F30D0A 00000000
```

> task.py

```python
# uncompyle6 version 2.11.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 2.7.15 (default, Feb 12 2019, 11:00:12) 
# [GCC 4.2.1 Compatible Apple LLVM 10.0.0 (clang-1000.11.45.5)]
# Embedded file name: task.py
# Compiled at: 1995-09-28 01:18:56
from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import random

class cipher:
    def __init__(self, key):
        self.key = md5(key.encode('utf8')).digest()
        self.padd = 0

    def encrypt(self, data):
        iv = get_random_string('AAAAAAAAAAAAAAAA')
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ta = self.cipher.encrypt(self.pad(data))
        return b64encode(iv + ta)

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
        x = self.cipher.decrypt(raw[AES.block_size:])
        return self.unpad(x)

    def pad(self, strr):
        x = 16 - len(strr) % 16
        final = strr + chr(x) * x
        self.padd = x
        return final

    def unpad(self, strr):
        return strr[:len(strr) - self.padd]

def get_random_string(strr):
    ch = ''
    for i in range(len(strr)):
        ch += chr(random.randint(23, 255))
    return ch

def phase1(arg1, arg2):
    res = ''
    for i in range(len(arg1)):
        res += chr(ord(arg1[i]) ^ ord(arg2[i]))
    return res

def main():
    random.seed(2020)
    last_ci = 'tMGb4+vbwHmn1Vq826krTWNtO0YHhOxrgz0SxBmsKiiV6/PlMyy1cavIOWuyCo8agFAOSDZhDY9OLXaKDqiFGA=='
    last_ci = b64decode(last_ci)
    print 'Welcome to SECURINETS CTF!'
    username = raw_input('Please enter the username:')
    password = raw_input('Please enter the password:')
    cipher1 = username + password
    tmp = get_random_string(cipher1)
    res = phase1(cipher1, tmp)
    cipher2 = ''
    for i in range(len(cipher1)):
        cipher2 += chr(ord(res[i]) + 1)

    cipher2 = cipher2[::-1]
    tool = cipher('securinets')
    last_c = tool.encrypt(cipher2)
    last_c = b64decode(last_c)
    if last_c == last_ci:
        print 'Good job!\nYou can submit with securinets{%s}' % (username + ':' + password)
    else:
        print ':( ...'

if __name__ == '__main__':
    main()
```

random seed가 고정이라 랜덤 문자열도 고정이라 last_ci를 aes decrypt해주고 역연산해주면 된다.

> solve.py

```python
# uncompyle6 version 2.11.5
# Python bytecode 2.7 (62211)
# Decompiled from: Python 2.7.15 (default, Feb 12 2019, 11:00:12) 
# [GCC 4.2.1 Compatible Apple LLVM 10.0.0 (clang-1000.11.45.5)]
# Embedded file name: task.py
# Compiled at: 1995-09-28 01:18:56
from hashlib import md5
from base64 import b64decode
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import random
from pwn import *

class cipher:

    def __init__(self, key):
        self.key = md5(key.encode('utf8')).digest()
        self.padd = 0

    def encrypt(self, data):
        iv = get_random_string('AAAAAAAAAAAAAAAA')
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ta = self.cipher.encrypt(self.pad(data))
        return b64encode(iv + ta)

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
        x = self.cipher.decrypt(raw[AES.block_size:])
        return self.unpad(x)

    def pad(self, strr):
        x = 16 - len(strr) % 16
        final = strr + chr(x) * x
        self.padd = x
        return final

    def unpad(self, strr):
        return strr[:len(strr) - self.padd]

def get_random_string(strr):
    ch = ''
    for i in range(len(strr)):
        ch += chr(random.randint(23, 255))
    return ch

def phase1(arg1, arg2):
    res = ''
    for i in range(len(arg1)):
        res += chr(ord(arg1[i]) ^ ord(arg2[i]))
    return res

def main():
        last_ci = 'tMGb4+vbwHmn1Vq826krTWNtO0YHhOxrgz0SxBmsKiiV6/PlMyy1cavIOWuyCo8agFAOSDZhDY9OLXaKDqiFGA=='
    random.seed(2020)
    tmp = get_random_string('A'*48)
    tool = cipher('securinets') # set
    a = tool.decrypt(last_ci)[::-1]
    b = "".join(chr(ord(a[i])-1) for i in range(len(a)))

    print hexdump(b)
    print hexdump(tmp)

    g = 'cf 0b b8 97 e6 c0 e7 95 b7 7c 70 8b 91 e7 4d 8b bc 80 f5 b1 16 14 db df 7d bf 8e 18 c3 6d c7 28 a4 b4 6c cf ba ba c3 f5 '.replace(' ','').decode('hex')
    h = 'a7 3f ca f3 85 f0 95 a6 81 4e 47 b3 a3 84 2f b3 89 e2 94 85 20 22 eb ee 49 db b8 2c fa 54 f6 1d 94 83 5e ac 82 8f a6 90 b4 c1 9b e3 eb db c0 79'.replace(' ','').decode('hex')
    flag =""
    for i in range(len(g)):
        flag += chr(ord(g[i])^ord(h[i]))
    print flag

if __name__ == '__main__':
    main()
```

**FLAG : `securinets{h4rdc0r3:62782cb85ba466014d649915072c85ee}`**

<br />

## KAVM

VM 문제다. op byte값 가져와서 vm에서 실행해준다. 

```c
int __cdecl main()
{
  int op; // eax

  while ( one )
  {
    ++index;
    op = get();
    vm(op);
  }
  return 0;
}
```

흥미로운건 이런 코드가 있는데 32글자 vm코드 내에서 글자 계산도 하는거 같아서 32글자 맞추고 디버깅해보면 이 부분과 xor, add연산을 해준다. 

```
.data:0804B1E0                 db  53h ; S
.data:0804B1E1                 db  7Ah ; z
.data:0804B1E2                 db  7Dh ; }
.data:0804B1E3                 db  68h ; h
.data:0804B1E4                 db  6Eh ; n
.data:0804B1E5                 db  72h ; r
.data:0804B1E6                 db  74h ; t
.data:0804B1E7                 db  7Ch ; |
.data:0804B1E8                 db  6Ch ; l
.data:0804B1E9                 db  64h ; d
.data:0804B1EA                 db  6Dh ; m
.data:0804B1EB                 db  63h ; c
.data:0804B1EC                 db  79h ; y
.data:0804B1ED                 db  4Ch ; L
.data:0804B1EE                 db  62h ; b
.data:0804B1EF                 db  63h ; c
.data:0804B1F0                 db  20h
.data:0804B1F1                 db  7Bh ; {
.data:0804B1F2                 db  3Dh ; =
.data:0804B1F3                 db  6Eh ; n
.data:0804B1F4                 db  78h ; x
.data:0804B1F5                 db  3Ah ; :
.data:0804B1F6                 db  3Ah ; :
.data:0804B1F7                 db  67h ; g
.data:0804B1F8                 db  57h ; W
.data:0804B1F9                 db  75h ; u
.data:0804B1FA                 db  36h ; 6
.data:0804B1FB                 db  66h ; f
.data:0804B1FC                 db  6Fh ; o
.data:0804B1FD                 db  36h ; 6
.data:0804B1FE                 db  23h ; #
.data:0804B1FF                 db  7Ch ; |
```

대충 이런식으로 짜여있다.

```python
tb=[0x53,0x7a,0x7d,0x68,0x6e,0x72,0x74,0x7c,0x6c,0x64,0x6d,0x63,0x79,0x4c,0x62,0x63,0x20,0x7b,0x3d,0x6e,0x78,0x3a,0x3a,0x67,0x57,0x75,0x36,0x66,0x6f,0x36,0x23,0x7c]
inp = [ord(i) for i in list(raw_input())]
assert len(inp) == 32
for i in range(0,32):
	inp[i] ^= (len(inp)-i)

if inp == tb:
	print 'Good Job! You win!'
else:
	print 'No...'
```

> solve.py

```python
tb=[0x53,0x7a,0x7d,0x68,0x6e,0x72,0x74,0x7c,0x6c,0x64,0x6d,0x63,0x79,0x4c,0x62,0x63,0x20,0x7b,0x3d,0x6e,0x78,0x3a,0x3a,0x67,0x57,0x75,0x36,0x66,0x6f,0x36,0x23,0x7c]

print ''.join(chr(tb[i]^(32-i)) for i in range(len(tb)))
```

**FLAG : `securinets{vm_pr0t3ct10n_r0ck5!}`**

<br />

## static EYELESS REVENGE

웬만한 symbol들을 다 복구하면 쉽게 풀 수 있다. 

_libc_csu_init 함수에서 `sub_400B6D` 함수를 먼저 실행시켜준다. 이거랑 똑같이 비슷하게 복잡하게 만들어놓은 함수가 하나 더 있긴한데 그거 무시해주면 된다. 어차피 실행되는건 `sub_400B6D` 함수다. 

```c
__int64 __fastcall _libc_csu_init(unsigned int a1, __int64 a2, __int64 a3)
{
  __int64 v3; // r13
  __int64 result; // rax
  signed __int64 v11; // r14
  __int64 v12; // rbx

  v3 = a3;
  result = sub_400418();
  v11 = off_6FB150 - &off_6FB138;
  if ( v11 )
  {
    v12 = 0LL;
    do
      result = (*(&off_6FB138 + v12++))(a1, a2, v3);
    while ( v11 != v12 );
  }
  return result;
}
```

해당 함수를 보게되면 첫글자가 s인지 비교하고 뒤에는 ecurinets{ 인지 비교해준다. 그리고 첫글자를 seed 값으로 주고 rand함수로 byte단위로 가져와서 절대값을 씌워준다. 그리고 뒤에는 xor해준다. 이제 값들을 다 구할 수 있으니까 역연산만 해주면 된다.

```c
void __noreturn sub_400B6D()
{
  v76 = __readfsqword(0x28u);
  memset(&v11, 0, 0xC8uLL);
  v11 = 246;
  v12 = 155;
  v13 = 5;
  v14 = 254;
  v15 = 54;
  v16 = 163;
  v17 = 62;
  v18 = 147;
  v19 = 200;
  v20 = 44;
  v21 = 178;
  v22 = 110;
  v23 = 51;
  v24 = 124;
  v25 = 147;
  v26 = 42;
  v27 = 196;
  v28 = 110;
  v29 = 164;
  v30 = 15;
  v31 = 140;
  v32 = 216;
  v33 = 125;
  v34 = 223;
  v35 = 174;
  v36 = 198;
  v37 = 124;
  v38 = 215;
  v39 = 239;
  v40 = 165;
  v41 = 113;
  v42 = 72;
  v43 = 200;
  v44 = 73;
  v45 = 58;
  v46 = 178;
  v47 = 120;
  v48 = 245;
  v49 = 204;
  v50 = 190;
  v51 = 154;
  v52 = 71;
  v53 = 210;
  v54 = 135;
  v55 = 16;
  v56 = 253;
  v57 = 120;
  v58 = 29;
  v59 = 0xCE8B83818D828BB9LL;
  v60 = 0xBCBBADABBDCE819ALL;
  v61 = 0xBAADCEBDBAABA0A7LL;
  v62 = 0xCFA8LL;
  v63 = 0LL;
  v64 = 0LL;
  v65 = 0;
  LODWORD(v2) = 0;
  while ( v2 < strlen(&v59) )
  {
    *(&v59 + v2) ^= 0xEEu;
    LODWORD(v2) = v2 + 1;
  }
  IO_puts(&v59);                                // Welcome to SECURINETS CTF!
  v66 = 0xCE8B83CE8B9887A9LL;
  v67 = 0x9D9D8F9ECE8B869ALL;
  v68 = 0xD48B9D8F9C869ELL;
  v69 = 0LL;
  v70 = 0LL;
  v71 = 0LL;
  v72 = 0;
  HIDWORD(v2) = 0;
  while ( SHIDWORD(v2) < strlen(&v66) )
  {
    *(&v66 + SHIDWORD(v2)) ^= 0xEEu;
    ++HIDWORD(v2);
  }
  puts(&v66, v2);                               // Give me the passphrase:
  IO_fgets(&input, 70LL, off_6FF088);
  v3 = 0;
  while ( input != 's' )
    ++v3;
  v0 = "ecurinets{";
  v8 = 0xDEADBEEFLL * strncmp(v74, "ecurinets{", 10LL);
  while ( v8 )
    puts(" SECURINETS FTW! ");
  _srandom(input);
  for ( i = 0; i <= 49; ++i )
  {
    v1 = rand();
    v9[i] = abs(v1);
  }
  for ( j = 0; j < strlen(v75); ++j )
    v10[j] = v9[j] ^ v75[j];
  v6 = 0;
  for ( k = 0; k <= 47; ++k )
    v6 += *(&v11 + k) ^ v10[k];
  if ( v6 )
  {
    IO_puts("NOOOOOOO");
  }
  else
  {
    v0 = &input;
    puts("Good Job!\nsubmit with\n%s", &input);
  }
  exit(0LL, v0);
}
```

> init.c

```c
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

int main(){
	unsigned char table[100];
	memset(table, 0x00, sizeof(table));
	srand((int)'s');
	for(int i=0; i<=49; i++){
		table[i] = abs(rand());
	}
	for(int i=0; i<=49; i++){
		printf("%d ",table[i]);
	}
}
```

> solve.py

```python
from pwn import *

a = p64(0xCE8B83818D828BB9) + p64(0xBCBBADABBDCE819A) + p64(0xBAADCEBDBAABA0A7) + p16(0xCFA8)
b = ''.join(chr(ord(i)^0xee) for i in a)

c = p64(0xCE8B83CE8B9887A9) + p64(0x9D9D8F9ECE8B869A) + p64(0xD48B9D8F9C869E)
d = ''.join(chr(ord(i)^0xee) for i in c)
print b
print d

table = map(int,'159 196 119 205 2 207 82 234 151 78 129 2 2 79 229 25 155 95 202 80 249 170 34 185 219 178 9 165 220 250 3 123 190 122 72 193 73 155 171 225 233 44 227 235 124 200 5 23 39 207'.split(' '))
table2 = map(int,'246 155 5 254 54 163 62 147 200 44 178 110 51 124 147 42 196 110 164 15 140 216 125 223 174 198 124 215 239 165 113 72 200 73 58 178 120 245 204 190 154 71 210 135 16 253 120 29'.split(' '))

print 'securinets{' + ''.join(chr(table[i]^table2[i]) for i in range(len(table2)))
```

**FLAG : `securinets{i_r34lly_b3l13v3_1n_ur_futur3_r3v3rs1ng_sk1ll5}`**

<br />

# Pwn

## UNCRACKABLE

hash rainbow table에 존재하지 않는 해쉬다. 

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  char s; // [rsp+Fh] [rbp-451h]
  char s1; // [rsp+10h] [rbp-450h]
  char v6; // [rsp+420h] [rbp-40h]
  char v7; // [rsp+44Fh] [rbp-11h]
  void *s2; // [rsp+450h] [rbp-10h]
  FILE *stream; // [rsp+458h] [rbp-8h]

  setvbuf(_bss_start, 0LL, 2, 0LL);
  __isoc99_scanf("%32s", &v6);
  sprintf(&s, "echo -n '%s'|md5sum", &v6);
  stream = popen(&s, "r");
  if ( !stream )
  {
    puts("Failed to run command");
    exit(1);
  }
  fgets(&s1, 33, stream);
  s2 = "3b9aafa12aceeccd29a154766194a964";
  v7 = memcmp(&s1, "3b9aafa12aceeccd29a154766194a964", 0x20uLL);
  if ( v7 )
    result = puts("not good enough");
  else
    result = system("cat flag");
  return result;
}
```

unintend같다. 이게 솔직히 왜 실행되는지 모르겠다. 

```bash
$ ./main
$BASH_VERSION
cat: flag: No such file or directory
```

> solve

```
$ ./main
$BASH_VERSION
FLAG{ASAS}
```

**FLAG : `securinets{memcmp_turned_out_to_be_shame_shame_shame!!}`**

<br />