---
title: Codeforces Round 935
date: 2024-03-27 14-21-44
categories: [CTF]
tags: [pwn, HTB]
image: /assets/image/htb.jpg
math: true
---

# A. Setting up Camp

```python
n = int(input())
for i in range(n):
    a, b, c = map(int, input().split())
    res = a + b//3
    du = b % 3
    conlai = (b % 3+c)

    if conlai // 3 == 0 and du != 0:
        print("-1")
    else:
        res += conlai//3
        conlai %= 3
        if conlai:
            res += 1
        print(res)
```

# B. Fireworks

```python
import builtins
n = int(input())
for i in range(n):
    a, b, m = map(int, input().split())
    print(m//a + m//b + 2)

```
