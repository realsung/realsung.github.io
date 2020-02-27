---
layout: post
type: note
title: GDB handle
alias: Pwnable
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
$ handle SIGABRT nostop
Signal        Stop	Print	Pass to program	Description
SIGABRT       No	Yes	Yes		Aborted
```

위와 같이해주면 SIGABRT가 떠도 계속 디버깅이 가능하다.