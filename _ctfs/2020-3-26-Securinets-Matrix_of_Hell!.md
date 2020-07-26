---
title: "2019 Securinets CTF Quals Matrix_of_Hell!"
date: 2020-3-26
ctf: Securinets CTF
layout: post
published : false
---

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  int v3; // eax
  int index2; // ST18_4
  size_t v5; // rbx
  signed int i; // [rsp+Ch] [rbp-24h]
  int k; // [rsp+Ch] [rbp-24h]
  int n; // [rsp+Ch] [rbp-24h]
  signed int ii; // [rsp+Ch] [rbp-24h]
  int jj; // [rsp+Ch] [rbp-24h]
  signed int j; // [rsp+10h] [rbp-20h]
  signed int m; // [rsp+10h] [rbp-20h]
  signed int v14; // [rsp+14h] [rbp-1Ch]
  signed int l; // [rsp+14h] [rbp-1Ch]
  int index1; // [rsp+18h] [rbp-18h]
  int v17; // [rsp+1Ch] [rbp-14h]

  v14 = 0;
  for ( i = 0; i <= 4; ++i )
  {
    for ( j = 0; j <= 4; ++j )
    {
      if ( v14 == 9 )
      {
        v14 = 10;
        --j;
      }
      else
      {
        a2 = j;
        a3 = (4 * (j + 6LL * i));
        *(table + a3) = v14++ + 65;
      }
    }
  }
  printf("PASSWORD:", a2, a3);
  gets(input);
  if ( strlen(input) != 14 || (sub_558D8CB6383A(), !v3) )
  {
    printf("ACCESS DENIED");
    exit(0);
  }
  index1 = 0;
  for ( k = 0; k < strlen(input); ++k )
  {
    for ( l = 0; l <= 4; ++l )
    {
      for ( m = 0; m <= 4; ++m )
      {
        if ( table[m + 6LL * l] == input[k] )
        {
          go[index1] = l + 65;
          index2 = index1 + 1;
          go[index2] = m + 49;
          index1 = index2 + 1;
        }
      }
    }
  }
  for ( n = 0; n < strlen(go); ++n )
    s2[n] = n % 4 ^ go[n];
  if ( strcmp(s1, s2) )
  {
    printf("ACCESS DENIED", s2);
    exit(0);
  }
  v17 = 0;
  puts("[+]GOOD JOB ! u can submit with this :");
  for ( ii = 3; ii < strlen(aAbcdefghijklmn) - 5; ++ii )
  {
    v17 += aAbcdefghijklmn[ii];
    *(&src + ii - 3) = aAbcdefghijklmn[ii];
  }
  for ( jj = 0; jj < strlen(&src); ++jj )
    *(&src + jj) ^= jj % 7;
  v5 = strlen(input) - 1;
  *(&src + strlen(&src)) = input[v5];
  strcpy(dest, &src);
  src = input[0];
  *(&src + (v17 - 40) % 5) = 95;
  *(&src + (v17 - 40) % 13) = 95;
  sprintf(byte_558D8CD650E0, "%d_%s_HAHAHA", (v17 - 40), &src);
  printf("%s", byte_558D8CD650E0);
  return 0LL;
}
```

table에 A~Z까지 값을 넣어준다. s1 값을 아니까 go를 알 수 있다. 그걸 토대로 password를 구할 수 있다.

> solve.py

```python
table =[0x00000041, 0x00000042, 0x00000043, 0x00000044, 0x00000045, 0x00000000, 0x00000046, 0x00000047, 0x00000048, 0x00000049, 0x0000004B, 0x00000000, 0x0000004C, 0x0000004D, 0x0000004E, 0x0000004F, 0x00000050, 0x00000000, 0x00000051, 0x00000052, 0x00000053, 0x00000054, 0x00000055, 0x00000000, 0x00000056, 0x00000057, 0x00000058, 0x00000059, 0x0000005A, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000]

s1 = 'B0C2A2C6A3A7C5@6B5F0A4G2B5A2'
go = ''
for i in range(len(s1)):
	go += chr(ord(s1[i])^(i%4))
print go
password = ""

for k in range(0,28,2):
	for l in range(5):
		for m in range(5):
			if go[k] == chr(65+l) and go[k+1] == chr(49+m):
				password += chr(table[(m+6*l)])

print password 
```

얻은 값을 가지고 입력하게 되면 결과 값을 얻을 수 있다.

```bash
$ ./rev.elf
PASSWORD:FACEBOOKISEVIL
[+]GOOD JOB ! u can submit with this :
1337_FD_DDLLLKMO_KUWRRRVL_HAHAHA
```

FLAG : `securinets{1337_FD_DDLLLKMO_KUWRRRVL_HAHAHA}`