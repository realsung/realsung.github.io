---
layout: post
type: note
title: GDB handle
alias: Pwnable
published : false
---

gdb 사용하다가 signal 뜰 때 디버깅 계속하려면 handle instuction을 사용하면 된다.

```
stop - nostop
print - noprint
pass - nopass
ignore - noignore
```

`info handle` 로 signal 받을 때의 정보들을 출력해준다. 

```
$ handle 14 nostop pass
Signal        Stop	Print	Pass to program	Description
SIGALRM       No	Yes	No		Alarm clock
```

위와 같이해주면 handle 14번이 떠도 계속 디버깅이 가능하다. 

```
$ handle SIGALRM noprint nostop pass
Signal        Stop	Print	Pass to program	Description
SIGALRM       No	No	Yes		Alarm clock
```

Segmentation fault

```
$ handle SIGSEGV noprint nostop pass
```

or 

```
$ handle SIGALRM ignore
```

## Reference 

http://man7.org/linux/man-pages/man7/signal.7.html

