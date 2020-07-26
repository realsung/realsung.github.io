---
layout: post
type: note
title: glibc 2.27 tcache unsorted bin
alias: Pwnable
published : false
---

`tcache` 에서 돌아가는 서버에서 unsorted bin attack할 때 0x420 이상 size를 free해줘야지 unsorted bin에 들어가고 fd/bk에 main_arena+88이 박힌다.