---
layout: post
type: note
title: tcache
alias: Pwnable
---



Tcache는 glibc 2.26 (ubuntu 17.10) 이후에 도입 된 기술이며, 목적은 힙 관리 성능을 향상시키는 것입니다.

처음에 0x10~0x400이 할당되면 fastbin이나 unsorted bin에 들어가지 않고 tcache bin에 들어갑니다.

Tcache는 tcache_entry와 tcache_perthread_struct의 두 가지 새로운 구조를 도입했습니다.

이것은 실제로 패스트 빈과 매우 유사하지만 다릅니다.

## tcache_entry

https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#tcache_entry

```c
/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */

typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;
```

tcache_entry는 사용 가능한 청크 구조를 연결하는 데 사용되며, 다음 포인터는 동일한 크기의 다음 청크를 가르킵니다.

다음은 청크의 사용자 데이터를 가리키고 fastbin의 fd는 청크의 시작 부분에있는 주소를 가르킵니다.

또한 tcache_entry는 사용 가능한 청크의 사용자 데이터 부분을 다중화합니다.

## tcache_perthread_struct

```c
/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */

typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

# define TCACHE_MAX_BINS                64

static __thread tcache_perthread_struct *tcache = NULL;
```

각 스레드는 전체 tcache의 관리 구조 인 tcache_prethread_struct를 유지 관리합니다. 총 TCACHE_MAX_BINS 카운터와 TCACHE_MAX_BINS 항목 tcache_entry가 있습니다.

tcache_entry는 fastbin과 마찬가지로 단일 링크 목록에서 동일한 크기의 (해제) 청크를 연결합니다. counts는 체인 당 최대 7 개의 청크와 함께 tcache_entry 체인의 사용 가능한 청크 수를 기록합니다.

다이어그램은 아마도 다음과 같습니다.

![](https://user-images.githubusercontent.com/32904385/76665174-26faef00-65ca-11ea-92a1-637680a80f0b.jpg)

## method

* tcache가 채워질 때까지 tcache에 넣는다. (기본 값 7)
* tcache가 다 채워지고 해제된 메모리는 fastbin이나 unsorted bin에 분류된다.
* tcache의 chunk는 병합되지 않는다.

* tcache가 비어있을 때 fastbin / smallbin / unsorted bin에 크기가 일치하는 청크가 있으면 fastbin / smallbin / unsorted bin의 청크가 가득 찰 때까지 tcache에 먼저 저장됩니다. 그런 다음 tcache에서 가져옵니다. 따라서 bin 및 tcache의 청크 순서가 반대로됩니다.

## __libc_malloc

malloc이 호출되면 MAYBE_INIT_TCACHE ()으로 갑니다. 

```c
void *

__libc_malloc (size_t bytes)

{

    ......

    ......

#if USE_TCACHE

  /* int_free also calls request2size, be careful to not pad twice.  */

  size_t tbytes;

/ / Calculate the actual size of the chunk according to the parameters passed in malloc, and calculate the subscript corresponding to tcache
  checked_request2size (bytes, tbytes);

  size_t tc_idx = csize2tidx (tbytes);



/ / Initialize tcache
  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;

If (tc_idx &lt; mp_.tcache_bins // The idx obtained from size is within the legal range
      /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appease gcc */

      && tcache

      && tcache->entries[tc_idx] != NULL) // tcache->entries[tc_idx] 有 chunk

    {

      return tcache_get (tc_idx);

    }

  DIAG_POP_NEEDS_COMMENT;

#endif
    ......

    ......

}
```

## __tcache_init ()

tcache가 비어있을 때 MAYBE_INIT_TCACHE ()가 tcache_init ()를 호출 한다.

```c
tcache_init(void)

{

mstate ar_ptr;
  void *victim = 0;

  const size_t bytes = sizeof (tcache_perthread_struct);

  if (tcache_shutting_down)

    return;

Arena_get (ar_ptr, bytes); // find available arena
Victim = _int_malloc (ar_ptr, bytes); // Request a chunk of sizeof(tcache_prethread_struct) size  if (!victim && ar_ptr != NULL)

    {

      ar_ptr = arena_get_retry (ar_ptr, bytes);

      victim = _int_malloc (ar_ptr, bytes);

    }

  if (ar_ptr != NULL)

    __libc_lock_unlock (ar_ptr->mutex);

  /* In a low memory situation, we may not be able to allocate memory

     - in which case, we just keep trying later.  However, we

     typically do this very early, so either there is sufficient

     memory, or there isn't enough memory to do non-trivial

     allocations anyway.  */

If (victim) // initialize tcache
    {

      tcache = (tcache_perthread_struct *) victim;

      memset (tcache, 0, sizeof (tcache_perthread_struct));

    }

}
```

tcache_init () 성공적으로 리턴 한 후 tcache_prethread_struct가 생성된다.

## tcache_put

```c
/* Caller must ensure that we know tc_idx is valid and there's room

   for more chunks.  */

static __always_inline void

tcache_put (mchunkptr chunk, size_t tc_idx)

{

  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  assert (tc_idx < TCACHE_MAX_BINS);

  e->next = tcache->entries[tc_idx];

  tcache->entries[tc_idx] = e;

  ++(tcache->counts[tc_idx]);
}
```

tcache list에 chunk를 추가하는 함수이다. 해제된 청크를 보호없이 tcache entries[tc_idx]에 추가해준다. 

_int_malloc, _int_free함수에서 호출된다. 

## _int_free

```c
static void

_int_free (mstate av, mchunkptr p, int have_lock)

{

  ......

  ......

#if USE_TCACHE

  {

    size_t tc_idx = csize2tidx (size);

    if (tcache

        && tc_idx < mp_.tcache_bins // 64

        && tcache->counts[tc_idx] < mp_.tcache_count) // 7

      {

        tcache_put (p, tc_idx);

        return;

      }

  }

#endif
  ......

  ......
```

free함수를 호출 후 _int_free 함수를 호출하고 tc_idx가 유효한 것으로 판단 할 때 tcache count [tc_idx]가 7 내에 있으면 tcache_put ()를 호출하고 tcache bin이 비었으면 fastbin, unsorted bin에 들어가지 않고 tcache bin에 들어간다. 

tcache에서는 전 버전들과 다르게 free할 때 dfb를 검사하지 않는다. 주소가 유효한지, 사이즈가 알맞은지 검사한다. 

## _int_malloc

```c
size_t tc_idx = csize2tidx (nb);
if (tcache && tc_idx < mp_.tcache_bins)
  {
    mchunkptr tc_victim;

    /* While bin not empty and tcache not full, copy chunks over.  */
    while (tcache->counts[tc_idx] < mp_.tcache_count
           && (pp = *fb) != NULL)
      {
        REMOVE_FB (fb, tc_victim, pp);
        if (tc_victim != 0)
          {
            tcache_put (tc_victim, tc_idx);
          }
      }
  }
```

