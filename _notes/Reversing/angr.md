---
layout: post
type: note
title: angr
alias: Reversing
---

> example

```python
import angr

p = angr.Project("r100.bin", auto_load_libs=False)
path_group = p.factory.path_group() 
print path_group.explore(find=0x400844,avoid=0x400855)
print path_group.found[0].state.posix.dumps(3)
```

> example

```python
import angr

p=angr.Project("./r100",load_options={'auto_load_libs':True})
ex=p.surveyors.Explorer(find=(0x400844,),avoid=(0x400855,))
ex.run()
key = ex.found[0].state.posix.dumps(3)
print 'Flag is : ' + key[:12]
```

