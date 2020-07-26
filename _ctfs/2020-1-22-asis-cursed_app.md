---
title: "2019 ASIS CTF Final Cursed app"
date: 2020-1-22
ctf: ASIS CTF
layout: post
published : false
---

```c

undefined8 FUN_001010e0(undefined8 uParm1,long lParm2)

{
  bool bVar1;
  int iVar2;
  FILE *__stream;
  long lVar3;
  char *__ptr;
  undefined local_e8 [208];
  
  bVar1 = false;
  iVar2 = _setjmp((__jmp_buf_tag *)local_e8);
  if (iVar2 != 0) {
    puts("please locate license file, run ./app license_key");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  __stream = fopen(*(char **)(lParm2 + 8),"r");
  if (__stream != (FILE *)0x0) {
    fseek(__stream,0,2);
    lVar3 = ftell(__stream);
    fseek(__stream,0,0);
    __ptr = (char *)malloc((long)(int)lVar3);
    if (__ptr != (char *)0x0) {
      fread(__ptr,1,(long)(int)lVar3,__stream);
    }
    fclose(__stream);
    iVar2 = ((int)*__ptr * 0xaf + 0x91) % 0x100;
    if (((((((((iVar2 * iVar2 * 0x164 + 0x202 + iVar2 * 0xeb) % (iVar2 * 0x67 + 2) == 0) &&
             (iVar2 = ((int)__ptr[1] * 0x5d + 0xda) % 0x100,
             (iVar2 * iVar2 * 0x3da + 0x354 + iVar2 * 0x3c) % (iVar2 * 0x56 + 0x35f) == 0)) &&
            (iVar2 = ((int)__ptr[2] * 5 + 0x95) % 0x100,
            (iVar2 * iVar2 * 0x19e + 0x3aa + iVar2 * 0x49) % (iVar2 * 0xb9 + 0xb2) == 0)) &&
           (((iVar2 = ((int)__ptr[3] * 0x35 + 0xd4) % 0x100,
             (iVar2 * iVar2 * 0x210 + 0xba + iVar2 * 0x20c) % (iVar2 * 0x7e + 0x38) == 0 &&
             (iVar2 = ((int)__ptr[4] * 0xb5 + 0xd) % 0x100,
             (iVar2 * iVar2 * 0x26a + 0x3ce + iVar2 * 0x130) % (iVar2 * 8 + 0x27f) == 0)) &&
            ((iVar2 = ((int)__ptr[5] * 0x5b + 2) % 0x100,
             (iVar2 * iVar2 * 5 + 0x4b + iVar2 * 0x2f7) % (iVar2 * 0x30e + 0x55) == 0 &&
             ((iVar2 = ((int)__ptr[6] * 0x43 + 0x76) % 0x100,
              (iVar2 * iVar2 * 0x37d + 0x1f1 + iVar2 * 0xed) % (iVar2 * 0x106 + 0xdd) == 0 &&
              (iVar2 = ((int)__ptr[7] * 0xe7 + 0x74) % 0x100,
              (iVar2 * iVar2 * 0x213 + 0x3e5 + iVar2 * 0x287) % (iVar2 * 0xf5 + 0x184) == 0))))))))
          && ((iVar2 = ((int)__ptr[8] * 0x77 + 0xdf) % 0x100,
              (iVar2 * iVar2 * 0x228 + 0x2ce + iVar2 * 0x1e7) % (iVar2 * 10 + 0x22a) == 0 &&
              (((((iVar2 = ((int)__ptr[9] * 0xcb + 0x88) % 0x100,
                  (iVar2 * iVar2 * 0x336 + 0x3bd + iVar2 * 0x95) % (iVar2 * 0x78 + 0x230) == 0 &&
                  (iVar2 = ((int)__ptr[10] * 0x51 + 0x96) % 0x100,
                  (iVar2 * iVar2 * 0x9d + 0x21a + iVar2 * 0x2b0) % (iVar2 * 0x144 + 0x265) == 0)) &&
                 (iVar2 = ((int)__ptr[0xb] * 0x29 + 0x8d) % 0x100,
                 (iVar2 * iVar2 * 0x56 + 0xcb + iVar2 * 0x2db) % (iVar2 * 0x15 + 0x203) == 0)) &&
                ((iVar2 = ((int)__ptr[0xc] * 0x73 + 0x5f) % 0x100,
                 (iVar2 * iVar2 * 0x2df + 0x88 + iVar2 * 0x178) % (iVar2 * 0x116 + 0x262) == 0 &&
                 (iVar2 = ((int)__ptr[0xd] * 0xf3 + 0xe4) % 0x100,
                 (iVar2 * iVar2 * 0x31b + 0x37c + iVar2 * 0xdd) % (iVar2 * 0xca + 0x33b) == 0)))) &&
               (iVar2 = ((int)__ptr[0xe] * 0x4f + 0x51) % 0x100,
               (iVar2 * iVar2 * 0x66 + 0x366 + iVar2 * 0x345) % (iVar2 * 0x234 + 0xf9) == 0)))))) &&
         (((iVar2 = ((int)__ptr[0xf] * 0x7b + 0x8e) % 0x100,
           (iVar2 * iVar2 * 0x12e + 0x282 + iVar2 * 0x2b0) % (iVar2 * 5 + 0xd5) == 0 &&
           (iVar2 = ((int)__ptr[0x10] * 0xa9 + 0x59) % 0x100,
           (iVar2 * iVar2 * 0xe + 0x2a8 + iVar2 * 0x272) % (iVar2 * 0x96 + 0x1c8) == 0)) &&
          (((iVar2 = ((int)__ptr[0x11] * 0xad + 0xe6) % 0x100,
            (iVar2 * iVar2 * 0x33e + 0x12e + iVar2 * 0x214) % (iVar2 * 0x19f + 0x1f1) == 0 &&
            (((iVar2 = ((int)__ptr[0x12] * 0xab + 0x9a) % 0x100,
              (iVar2 * iVar2 * 0x10f + 0xe2 + iVar2 * 0x72) % (iVar2 * 0x20 + 0x292) == 0 &&
              (iVar2 = ((int)__ptr[0x13] * 0x4b + 0xb8) % 0x100,
              (iVar2 * iVar2 * 0x366 + 0x39 + iVar2 * 0x35a) % (iVar2 * 0x37d + 0x1a8) == 0)) &&
             (iVar2 = ((int)__ptr[0x14] * 0xf5 + 0x5b) % 0x100,
             (iVar2 * iVar2 * 0x375 + 0x9d + iVar2 * 0x2f3) % (iVar2 * 0x6a + 0x3d7) == 0)))) &&
           (((iVar2 = ((int)__ptr[0x15] * 0xed + 0x22) % 0x100,
             (iVar2 * iVar2 * 0x36c + 0x173 + iVar2 * 0x189) % (iVar2 * 0x66 + 0x196) == 0 &&
             (iVar2 = ((int)__ptr[0x16] * 0x3d + 0x69) % 0x100,
             (iVar2 * iVar2 * 0x3cb + 0x214 + iVar2 * 0x3c0) % (iVar2 * 0x3e + 0x390) == 0)) &&
            (iVar2 = ((int)__ptr[0x17] * 0x9f + 0x2c) % 0x100,
            (iVar2 * iVar2 * 0x215 + 0x7a + iVar2 * 0x1d8) % (iVar2 * 0x29 + 0x32) == 0)))))))) &&
        ((((iVar2 = ((int)__ptr[0x18] * 0x77 + 0xef) % 0x100,
           (iVar2 * iVar2 * 0xa7 + 0x308 + iVar2 * 0x21f) % (iVar2 * 0x38 + 0x290) == 0 &&
           (iVar2 = ((int)__ptr[0x19] * 0xb3 + 0x70) % 0x100,
           (iVar2 * iVar2 * 0xf8 + 0x19e + iVar2 * 0x3ce) % (iVar2 * 0x87 + 0x52) == 0)) &&
          (((iVar2 = ((int)__ptr[0x1a] * 0x47 + 0xae) % 0x100,
            (iVar2 * iVar2 * 0x2f3 + 0x115 + iVar2 * 0x1cf) % (iVar2 * 10 + 0x113) == 0 &&
            (((iVar2 = ((int)__ptr[0x1b] * 0xbf + 0x90) % 0x100,
              (iVar2 * iVar2 * 0xe3 + 0x234 + iVar2 * 0x2a6) % (iVar2 * 0x37 + 0x27a) == 0 &&
              (iVar2 = ((int)__ptr[0x1c] * 0x51 + 0x9b) % 0x100,
              (iVar2 * iVar2 * 0x379 + 0x330 + iVar2 * 0x210) % (iVar2 * 0x173 + 0x2ea) == 0)) &&
             (iVar2 = ((int)__ptr[0x1d] * 0x57 + 200) % 0x100,
             (iVar2 * iVar2 * 0x14d + 0x25 + iVar2 * 0x2e0) % (iVar2 * 0x2e6 + 0xd) == 0)))) &&
           (((iVar2 = ((int)__ptr[0x1e] * 0xa7 + 0xa0) % 0x100,
             (iVar2 * iVar2 * 0x27c + 0xd5 + iVar2 * 200) % (iVar2 * 0x382 + 0x265) == 0 &&
             (iVar2 = ((int)__ptr[0x1f] * 0xe7 + 0x66) % 0x100,
             (iVar2 * iVar2 * 0x300 + 0x2e2 + iVar2 * 0x1a) % (iVar2 * 0x18a + 0x3e1) == 0)) &&
            (iVar2 = ((int)__ptr[0x20] * 0x71 + 0xd9) % 0x100,
            (iVar2 * iVar2 * 0x8a + 0xfc + iVar2 * 0x34b) % (iVar2 * 0x14d + 0x244) == 0)))))) &&
         (((((iVar2 = ((int)__ptr[0x21] * 0xaf + 9) % 0x100,
             (iVar2 * iVar2 * 0x1ae + 0x2cb + iVar2 * 0x164) % (iVar2 * 0x69 + 0x1fc) == 0 &&
             (iVar2 = ((int)__ptr[0x22] * 0xdb + 0xa6) % 0x100,
             (iVar2 * iVar2 * 0xac + 0x32c + iVar2 * 0x2ca) % (iVar2 * 2 + 0x124) == 0)) &&
            ((iVar2 = ((int)__ptr[0x23] * 0xb3 + 0x39) % 0x100,
             (iVar2 * iVar2 * 0x358 + 0x2b9 + iVar2 * 0x3be) % (iVar2 * 0x1f1 + 0x3be) == 0 &&
             ((((iVar2 = ((int)__ptr[0x24] * 0x97 + 0x1b) % 0x100,
                (iVar2 * iVar2 * 0x394 + 0x15 + iVar2 * 0x397) % (iVar2 * 0x4b + 699) == 0 &&
                (iVar2 = ((int)__ptr[0x25] * 0x3d + 0xf0) % 0x100,
                (iVar2 * iVar2 * 0x141 + 0x1ec + iVar2 * 0x3b9) % (iVar2 * 0x78 + 0x199) == 0)) &&
               (iVar2 = ((int)__ptr[0x26] * 0x29 + 0x76) % 0x100,
               (iVar2 * iVar2 * 0x7b + 0x3c4 + iVar2 * 0x10c) % (iVar2 * 0x4a + 0x14e) == 0)) &&
              ((iVar2 = ((int)__ptr[0x27] * 0x2d + 0x96) % 0x100,
               (iVar2 * iVar2 * 0x264 + 0x16c + iVar2 * 0x210) % (iVar2 * 0xd + 0x27d) == 0 &&
               (iVar2 = ((int)__ptr[0x28] * 0x4f + 0xd7) % 0x100,
               (iVar2 * iVar2 * 0xd6 + 0x3a6 + iVar2 * 0x28) % (iVar2 * 0x3ba + 0xa6) == 0))))))))
           && (iVar2 = ((int)__ptr[0x29] * 0x3f + 0xa0) % 0x100,
              (iVar2 * iVar2 * 0x388 + 0x34d + iVar2 * 0x15a) % (iVar2 * 0xf0 + 0x3d) == 0)) &&
          ((iVar2 = ((int)__ptr[0x2a] * 0xd3 + 0x72) % 0x100,
           (iVar2 * iVar2 * 0x22f + 0x299 + iVar2 * 0x22a) % (iVar2 * 0x93 + 0x379) == 0 &&
           (iVar2 = ((int)__ptr[0x2b] * 0x79 + 2) % 0x100,
           (iVar2 * iVar2 * 0x2cf + 0x32b + iVar2 * 0x3df) % (iVar2 * 0x82 + 0x195) == 0)))))))) &&
       ((((((iVar2 = ((int)__ptr[0x2c] * 0x75 + 0xe6) % 0x100,
            (iVar2 * iVar2 * 0x21d + 300 + iVar2 * 0x134) % (iVar2 * 0x27 + 0x29) == 0 &&
            (((iVar2 = ((int)__ptr[0x2d] * 0x51 + 0x52) % 0x100,
              (iVar2 * iVar2 * 0x234 + 0x229 + iVar2 * 0x253) % (iVar2 * 0x23 + 0x205) == 0 &&
              (iVar2 = ((int)__ptr[0x2e] * 0x55 + 0xa3) % 0x100,
              (iVar2 * iVar2 * 0x3b0 + 0x3b0 + iVar2 * 0xe3) % (iVar2 * 0x8a + 0xd9) == 0)) &&
             (iVar2 = ((int)__ptr[0x2f] * 0xed + 0xa5) % 0x100,
             (iVar2 * iVar2 * 0x203 + 0x14b + iVar2 * 0x306) % (iVar2 * 0x24 + 0x28c) == 0)))) &&
           (((iVar2 = ((int)__ptr[0x30] * 0x81 + 0x7f) % 0x100,
             (iVar2 * iVar2 * 0x362 + 0x14 + iVar2 * 0x1a4) % (iVar2 * 0xb + 0x15a) == 0 &&
             (iVar2 = ((int)__ptr[0x31] * 0x19 + 0xeb) % 0x100,
             (iVar2 * iVar2 * 0xb8 + 0x140 + iVar2 * 0x67) % (iVar2 * 0x211 + 0x17e) == 0)) &&
            (iVar2 = ((int)__ptr[0x32] * 0x9b + 0x3a) % 0x100,
            (iVar2 * iVar2 * 0x357 + 0xa0 + iVar2 * 0x33c) % (iVar2 * 0x46 + 0x10e) == 0)))) &&
          ((iVar2 = ((int)__ptr[0x33] * 0x55 + 0xf0) % 0x100,
           (iVar2 * iVar2 * 0x3b7 + 0xd5 + iVar2 * 0x234) % (iVar2 * 10 + 0x207) == 0 &&
           (iVar2 = ((int)__ptr[0x34] * 0x49 + 0x3d) % 0x100,
           (iVar2 * iVar2 * 0x282 + 0x362 + iVar2 * 0x79) % (iVar2 * 7 + 0x142) == 0)))) &&
         ((iVar2 = ((int)__ptr[0x35] * 0x81 + 0x56) % 0x100,
          (iVar2 * iVar2 * 0x3d + 0x181 + iVar2 * 0x326) % (iVar2 * 0x17 + 0x14f) == 0 &&
          (((iVar2 = ((int)__ptr[0x36] * 0x9b + 0xb1) % 0x100,
            (iVar2 * iVar2 * 399 + 0x24 + iVar2 * 0xc4) % (iVar2 * 0x65 + 0xda) == 0 &&
            (iVar2 = ((int)__ptr[0x37] * 0x99 + 0x7e) % 0x100,
            (iVar2 * iVar2 * 0x360 + 0x2aa + iVar2 * 0x116) % (iVar2 * 0x3c + 0x142) == 0)) &&
           (iVar2 = ((int)__ptr[0x38] * 0xe3 + 0xf5) % 0x100,
           (iVar2 * iVar2 * 0x123 + 0x1f8 + iVar2 * 0x152) % (iVar2 * 0x51 + 700) == 0)))))) &&
        ((iVar2 = ((int)__ptr[0x39] * 0xc3 + 0x16) % 0x100,
         (iVar2 * iVar2 * 0x300 + 0x13 + iVar2 * 0x3ca) % (iVar2 * 0x148 + 0x1e1) == 0 &&
         (iVar2 = ((int)__ptr[0x3a] * 0x79 + 0x25) % 0x100,
         (iVar2 * iVar2 * 0x2a9 + 0x349 + iVar2 * 0x203) % (iVar2 * 7 + 0xbb) == 0)))))) {
      puts("Congratz! You got the correct flag!!");
      bVar1 = true;
    }
    if (!bVar1) {
      puts("Bummer! You got the wrong flag!!");
    }
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  longjmp((__jmp_buf_tag *)local_e8,1);
}
```

> solve.py

```python
import angr
import claripy
import logging

logging.basicConfig()
flag_hash = 'dd791346264fc02ddcd2466b9e8b2b2bba8057d61fbbc824d25c7957c127250d' # sha-256
p = angr.Project('cursed_app.elf',load_options={'auto_load_libs': False})

# cfg = p.analyses.CFGFast()
# print(cfg.graph.nodes()) # Node Chk

base = 0x400000
file = 'tmp'
flag = claripy.BVS('flag',8*0x3b) # 59
state = p.factory.entry_state(args=["cursed_app.elf", file])

for byte in flag.chop(8):
	state.add_constraints(byte >= '\x20')
	state.add_constraints(byte <= '\x7e')

state.add_constraints(flag.chop(8)[0] == 'A')
state.add_constraints(flag.chop(8)[1] == 'S')
state.add_constraints(flag.chop(8)[2] == 'I')
state.add_constraints(flag.chop(8)[3] == 'S')
state.add_constraints(flag.chop(8)[4] == '{')
state.add_constraints(flag.chop(8)[-1] == '}')

file_chk = angr.storage.file.SimFile(file,flag)
state.fs.insert(file, file_chk)

simgr = p.factory.simgr(state)

block = [0x1177, 0x11be, 0x11f6, 0x1231, 0x1269, 0x12a3, 0x12d6, 0x1312, 0x1351, 0x138c, 0x13ca, 0x140d, 0x1445, 0x1481, 0x14c2, 0x14fb, 0x1536, 0x1572, 0x15b3, 0x15ee, 0x1629, 0x166a, 0x16a6, 0x16df, 0x1715, 0x1750, 0x178c, 0x17c7, 0x1805, 0x1843, 0x187b, 0x18c1, 0x18fd, 0x193b, 0x1977, 0x19b3, 0x19f2, 0x1a2b, 0x1a66, 0x1a9c, 0x1ad7, 0x1b17, 0x1b52, 0x1b91, 0x1bcd, 0x1c05, 0x1c3e, 0x1c7c, 0x1cba, 0x1cf3, 0x1d2e, 0x1d6f, 0x1daa, 0x1de0, 0x1e19, 0x1e54, 0x1e90, 0x1ece, 0x1f06, 0x1f3b]

for i in range(len(block)):
	simgr.explore(find=base+block[i],avoid=base+0x0000000000001F77)
	found = simgr.found[0]
	print(found.solver.eval(flag,cast_to=bytes))
	simgr.move('found', 'active') # 한 블록에 도달하면 다음꺼 찾기위해서 넣음.
	print(simgr.active)
```

**FLAG : `ASIS{y0u_c4N_s33_7h15_15_34513R_7h4n_Y0u_7h1nk_r16h7?__!!!}`**

