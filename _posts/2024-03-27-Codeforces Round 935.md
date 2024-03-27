---
title: Codeforces Round 935
date: 2024-03-27 14-21-44
categories: [CTF]
tags: [pwn, HTB]
image: /assets/image/htb.jpg
math: true
---

# A. Setting up Camp
[link](https://codeforces.com/contest/1945)
## Tóm tắt đề bài

- Có 3 nhóm người: `a` người hướng nội, `b` người hướng ngoại, `c` người bình thường - Người hướng nội chỉ ở lều có 1 người - Người hướng ngoại chỉ ở lều với 2 người (lều 3 người) - Người bình thường có thể ở lều 1, 2 hoặc 3 người
  > tìm lều tối thiểu, nếu không thể bố trí đúng yêu cầu `output = -1`

## Hướng giải quyết

- Số lều cho người hướng nội sẽ là = `a`
- Số lều cho người hướng ngoại sẽ là `b//3` và dư `b%3`
- Số lều cho người hướng ngoại (còn lại) và người bình thường là `b%3 + c`
- Trường hợp `-1` ta sẽ kiểm tra `b%3 != 0` vì còn dư người `b` và khi ghép người `c` nhưng không đủ không đủ tạo thành 1 lều 3 người (`(b % 3+c)//3 == 0`).

<details> 
<summary> <h3> solution </h3> </summary>

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

</details>
